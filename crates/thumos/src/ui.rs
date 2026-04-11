//! Three-zone UI framework for the 240x320 display.
//!
//! Layout:
//! - **Status bar**: top 20 pixels — connectivity, battery, mode indicators
//! - **Content area**: middle 270 pixels — active screen content
//! - **Softkey bar**: bottom 30 pixels — context-sensitive softkey labels
//!
//! The [`UiManager`] owns the screen stack (for back-navigation) and dispatches
//! input events to the active [`Screen`]. Rendering is split into three passes:
//! status bar, content (delegated to the screen), and softkeys.
//!
//! ## Framebuffer format
//!
//! RGB565, 16-bit per pixel, matching the kernel's display driver and the eidolon
//! crate's `Framebuffer`. The kernel renders into a flat `[u16]` buffer that maps
//! directly to the hardware framebuffer at `kconfig::FB_BASE`.
//!
//! ## Font
//!
//! Text rendering uses the same 8x16 bitmap font as eidolon (`crates/eidolon/src/font.rs`).
//! The font module is duplicated here because eidolon depends on `std` (via `Vec`)
//! and cannot be linked into the `#![no_std]` kernel.

// WHY: UI framework wired in Phase 07 but screens are not yet called from kinit.
#![expect(dead_code, reason = "UI framework created in Phase 07 Wave 1, kinit wiring pending")]

extern crate alloc;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Display layout constants
// ---------------------------------------------------------------------------

/// Display width in pixels (AGM M7 QVGA).
pub const SCREEN_WIDTH: u16 = 240;

/// Display height in pixels (AGM M7 QVGA).
pub const SCREEN_HEIGHT: u16 = 320;

/// Status bar height in pixels. Fits one font row (16px) plus 4px padding.
pub const STATUS_BAR_HEIGHT: u16 = 20;

/// Softkey bar height in pixels. Fits one font row (16px) plus 14px padding.
pub const SOFTKEY_BAR_HEIGHT: u16 = 30;

/// Content area height, derived from total minus status bar and softkey bar.
pub const CONTENT_HEIGHT: u16 = SCREEN_HEIGHT - STATUS_BAR_HEIGHT - SOFTKEY_BAR_HEIGHT;

/// Y-offset where the content area begins.
pub const CONTENT_Y: u16 = STATUS_BAR_HEIGHT;

/// Content framebuffer size in pixels (width * content height).
pub const CONTENT_PIXELS: usize = SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize;

// ---------------------------------------------------------------------------
// Font constants (matching eidolon 8x16 bitmap font)
// ---------------------------------------------------------------------------

/// Width of each character cell in pixels.
pub const CHAR_WIDTH: u16 = 8;

/// Height of each character cell in pixels.
pub const CHAR_HEIGHT: u16 = 16;

/// First printable ASCII code in the font table (space).
const FONT_FIRST: u32 = 0x20;

/// Last printable ASCII code in the font table (tilde).
const FONT_LAST: u32 = 0x7E;

/// Number of glyphs in the font table.
const FONT_CHAR_COUNT: usize = (FONT_LAST - FONT_FIRST + 1) as usize;

/// Bitmap font data: 95 glyphs, 16 rows each, 8 pixels wide.
///
/// Indexed as `FONT_DATA[char_code - 0x20]`. Each byte is one row; bit 7 is
/// the leftmost pixel. Identical to `crates/eidolon/src/font.rs`.
///
/// `pub(crate)` because `screen_home` uses it for scaled text rendering.
#[rustfmt::skip]
pub(crate) static FONT_DATA: [[u8; 16]; FONT_CHAR_COUNT] = [
    // 0x20 space
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x21 !
    [0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00],
    // 0x22 "
    [0x00,0x6C,0x6C,0x6C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x23 #
    [0x00,0x36,0x36,0x7F,0x36,0x36,0x7F,0x36,0x36,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x24 $
    [0x00,0x08,0x3E,0x6B,0x68,0x3E,0x0B,0x6B,0x3E,0x08,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x25 %
    [0x00,0x60,0x66,0x0C,0x18,0x30,0x66,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x26 &
    [0x00,0x38,0x6C,0x68,0x36,0x5B,0xCE,0xCC,0x76,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x27 '
    [0x00,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x28 (
    [0x00,0x0C,0x18,0x30,0x30,0x30,0x30,0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x29 )
    [0x00,0x30,0x18,0x0C,0x0C,0x0C,0x0C,0x0C,0x18,0x30,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x2A *
    [0x00,0x00,0x00,0x36,0x1C,0x7F,0x1C,0x36,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x2B +
    [0x00,0x00,0x18,0x18,0x18,0x7E,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x2C ,
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x18,0x30,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x2D -
    [0x00,0x00,0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x2E .
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x2F /
    [0x00,0x02,0x06,0x0C,0x18,0x30,0x60,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x30 0
    [0x00,0x3C,0x66,0x6E,0x76,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x31 1
    [0x00,0x18,0x38,0x18,0x18,0x18,0x18,0x18,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x32 2
    [0x00,0x3C,0x66,0x06,0x0C,0x18,0x30,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x33 3
    [0x00,0x3C,0x66,0x06,0x1C,0x06,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x34 4
    [0x00,0x0C,0x1C,0x3C,0x6C,0x7E,0x0C,0x0C,0x1E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x35 5
    [0x00,0x7E,0x60,0x60,0x7C,0x06,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x36 6
    [0x00,0x1C,0x30,0x60,0x7C,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x37 7
    [0x00,0x7E,0x06,0x06,0x0C,0x18,0x30,0x30,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x38 8
    [0x00,0x3C,0x66,0x66,0x3C,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x39 9
    [0x00,0x3C,0x66,0x66,0x66,0x3E,0x06,0x0C,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3A :
    [0x00,0x00,0x00,0x38,0x38,0x00,0x38,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3B ;
    [0x00,0x00,0x00,0x38,0x38,0x00,0x38,0x18,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3C <
    [0x00,0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3D =
    [0x00,0x00,0x00,0x7E,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3E >
    [0x00,0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x3F ?
    [0x00,0x3C,0x66,0x06,0x0C,0x18,0x00,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x40 @
    [0x00,0x3C,0x66,0x76,0x76,0x76,0x60,0x62,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x41 A
    [0x00,0x18,0x3C,0x66,0x66,0x7E,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x42 B
    [0x00,0x7C,0x66,0x66,0x7C,0x66,0x66,0x66,0x7C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x43 C
    [0x00,0x3C,0x66,0x60,0x60,0x60,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x44 D
    [0x00,0x78,0x6C,0x66,0x66,0x66,0x66,0x6C,0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x45 E
    [0x00,0x7E,0x60,0x60,0x7C,0x60,0x60,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x46 F
    [0x00,0x7E,0x60,0x60,0x7C,0x60,0x60,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x47 G
    [0x00,0x3C,0x66,0x60,0x60,0x6E,0x66,0x66,0x3E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x48 H
    [0x00,0x66,0x66,0x66,0x7E,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x49 I
    [0x00,0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4A J
    [0x00,0x1E,0x06,0x06,0x06,0x06,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4B K
    [0x00,0x66,0x6C,0x78,0x70,0x78,0x6C,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4C L
    [0x00,0x60,0x60,0x60,0x60,0x60,0x60,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4D M
    [0x00,0x63,0x77,0x7F,0x6B,0x63,0x63,0x63,0x63,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4E N
    [0x00,0x66,0x76,0x7E,0x6E,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x4F O
    [0x00,0x3C,0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x50 P
    [0x00,0x7C,0x66,0x66,0x7C,0x60,0x60,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x51 Q
    [0x00,0x3C,0x66,0x66,0x66,0x66,0x76,0x6C,0x36,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x52 R
    [0x00,0x7C,0x66,0x66,0x7C,0x6C,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x53 S
    [0x00,0x3C,0x66,0x60,0x3C,0x06,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x54 T
    [0x00,0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x55 U
    [0x00,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x56 V
    [0x00,0x66,0x66,0x66,0x66,0x66,0x3C,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x57 W
    [0x00,0x63,0x63,0x63,0x6B,0x7F,0x77,0x63,0x63,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x58 X
    [0x00,0x66,0x66,0x3C,0x18,0x3C,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x59 Y
    [0x00,0x66,0x66,0x66,0x3C,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5A Z
    [0x00,0x7E,0x06,0x0C,0x18,0x30,0x60,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5B [
    [0x00,0x3C,0x30,0x30,0x30,0x30,0x30,0x30,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5C backslash
    [0x00,0x40,0x60,0x30,0x18,0x0C,0x06,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5D ]
    [0x00,0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5E ^
    [0x00,0x18,0x3C,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x5F _
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x60 `
    [0x00,0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x61 a
    [0x00,0x00,0x00,0x3C,0x06,0x3E,0x66,0x66,0x3E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x62 b
    [0x00,0x60,0x60,0x7C,0x66,0x66,0x66,0x66,0x7C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x63 c
    [0x00,0x00,0x00,0x3C,0x66,0x60,0x60,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x64 d
    [0x00,0x06,0x06,0x3E,0x66,0x66,0x66,0x66,0x3E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x65 e
    [0x00,0x00,0x00,0x3C,0x66,0x7E,0x60,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x66 f
    [0x00,0x1C,0x30,0x30,0x7C,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x67 g
    [0x00,0x00,0x00,0x3E,0x66,0x66,0x3E,0x06,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x68 h
    [0x00,0x60,0x60,0x7C,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x69 i
    [0x00,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6A j
    [0x00,0x0C,0x00,0x1C,0x0C,0x0C,0x0C,0x0C,0x78,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6B k
    [0x00,0x60,0x60,0x66,0x6C,0x78,0x6C,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6C l
    [0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6D m
    [0x00,0x00,0x00,0x66,0x7F,0x7F,0x6B,0x63,0x63,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6E n
    [0x00,0x00,0x00,0x7C,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x6F o
    [0x00,0x00,0x00,0x3C,0x66,0x66,0x66,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x70 p
    [0x00,0x00,0x00,0x7C,0x66,0x66,0x66,0x7C,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x71 q
    [0x00,0x00,0x00,0x3E,0x66,0x66,0x66,0x3E,0x06,0x06,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x72 r
    [0x00,0x00,0x00,0x6C,0x76,0x60,0x60,0x60,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x73 s
    [0x00,0x00,0x00,0x3C,0x66,0x38,0x06,0x66,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x74 t
    [0x00,0x30,0x30,0x7C,0x30,0x30,0x30,0x30,0x1C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x75 u
    [0x00,0x00,0x00,0x66,0x66,0x66,0x66,0x66,0x3E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x76 v
    [0x00,0x00,0x00,0x66,0x66,0x66,0x66,0x3C,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x77 w
    [0x00,0x00,0x00,0x63,0x63,0x6B,0x7F,0x77,0x63,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x78 x
    [0x00,0x00,0x00,0x66,0x3C,0x18,0x3C,0x66,0x66,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x79 y
    [0x00,0x00,0x00,0x66,0x66,0x66,0x3E,0x06,0x3C,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7A z
    [0x00,0x00,0x00,0x7E,0x06,0x0C,0x30,0x60,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7B {
    [0x00,0x0E,0x18,0x18,0x70,0x18,0x18,0x18,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7C |
    [0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7D }
    [0x00,0x70,0x18,0x18,0x0E,0x18,0x18,0x18,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
    // 0x7E ~
    [0x00,0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],
];

// ---------------------------------------------------------------------------
// RGB565 colors
// ---------------------------------------------------------------------------

/// RGB565 color constants for kernel UI rendering.
///
/// Matches `crates/eidolon/src/color.rs` constants. Using raw `u16` values
/// avoids depending on the eidolon crate (which requires `std`).
pub mod color {
    /// Black (0x0000).
    pub const BLACK: u16 = 0x0000;
    /// White (0xFFFF).
    pub const WHITE: u16 = 0xFFFF;
    /// Red (0xF800).
    pub const RED: u16 = 0xF800;
    /// Green (0x07E0).
    pub const GREEN: u16 = 0x07E0;
    /// Blue (0x001F).
    pub const BLUE: u16 = 0x001F;
    /// Yellow (0xFFE0).
    pub const YELLOW: u16 = 0xFFE0;
    /// Dark grey for dimmed indicators.
    pub const DARK_GREY: u16 = 0x4208;

    /// Convert 24-bit RGB888 to RGB565 by truncating least significant bits.
    pub const fn from_rgb(r: u8, g: u8, b: u8) -> u16 {
        let r5 = (r >> 3) as u16;
        let g6 = (g >> 2) as u16;
        let b5 = (b >> 3) as u16;
        (r5 << 11) | (g6 << 5) | b5
    }
}

// ---------------------------------------------------------------------------
// Framebuffer drawing primitives
// ---------------------------------------------------------------------------

/// Set a single pixel in a flat `u16` framebuffer.
///
/// Out-of-bounds coordinates are silently ignored.
pub fn set_pixel(fb: &mut [u16], fb_width: u16, x: u16, y: u16, color: u16) {
    let idx = y as usize * fb_width as usize + x as usize;
    if let Some(px) = fb.get_mut(idx) {
        *px = color;
    }
}

/// Fill a rectangular region in the framebuffer.
///
/// Clips to the framebuffer bounds. `fb_width` and `fb_height` define the
/// logical dimensions; `fb.len()` must equal `fb_width * fb_height`.
pub fn fill_rect(
    fb: &mut [u16],
    fb_width: u16,
    fb_height: u16,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    color: u16,
) {
    let x_end = x.saturating_add(w).min(fb_width);
    let y_end = y.saturating_add(h).min(fb_height);
    for row in y..y_end {
        for col in x..x_end {
            let idx = row as usize * fb_width as usize + col as usize;
            if let Some(px) = fb.get_mut(idx) {
                *px = color;
            }
        }
    }
}

/// Render one character at pixel position `(x, y)` into a `u16` framebuffer.
///
/// Characters outside the printable ASCII range are silently skipped.
pub fn draw_char(
    fb: &mut [u16],
    fb_width: u16,
    x: u16,
    y: u16,
    ch: char,
    fg: u16,
    bg: u16,
) {
    let code = u32::from(ch);
    if !(FONT_FIRST..=FONT_LAST).contains(&code) {
        return;
    }
    // code - FONT_FIRST is 0..=94, always fits in usize.
    let glyph = &FONT_DATA[(code - FONT_FIRST) as usize];
    for (row, &byte) in glyph.iter().enumerate() {
        for col in 0u16..8 {
            let bit = (byte >> (7 - col)) & 1;
            let c = if bit != 0 { fg } else { bg };
            let px = x.saturating_add(col);
            let py = y.saturating_add(row as u16);
            set_pixel(fb, fb_width, px, py, c);
        }
    }
}

/// Render a string starting at pixel position `(x, y)`.
///
/// Characters are placed left-to-right with no wrapping. Out-of-bounds
/// pixels are clipped by [`set_pixel`].
pub fn draw_str(
    fb: &mut [u16],
    fb_width: u16,
    x: u16,
    y: u16,
    s: &str,
    fg: u16,
    bg: u16,
) {
    for (i, ch) in s.chars().enumerate() {
        let cx = x.saturating_add((i as u16).saturating_mul(CHAR_WIDTH));
        draw_char(fb, fb_width, cx, y, ch, fg, bg);
    }
}

/// Render a string horizontally centered in a region of width `region_width`,
/// starting at `region_x`.
pub fn draw_str_centered(
    fb: &mut [u16],
    fb_width: u16,
    region_x: u16,
    region_width: u16,
    y: u16,
    s: &str,
    fg: u16,
    bg: u16,
) {
    let text_width = s.len() as u16 * CHAR_WIDTH;
    let x = region_x.saturating_add(region_width.saturating_sub(text_width) / 2);
    draw_str(fb, fb_width, x, y, s, fg, bg);
}

/// Return the pixel width of a string rendered with this font.
pub fn str_pixel_width(s: &str) -> u16 {
    (s.len() as u16).saturating_mul(CHAR_WIDTH)
}

// ---------------------------------------------------------------------------
// Input event types (kernel-side, mirroring haphe::input::Key)
// ---------------------------------------------------------------------------

/// Key codes matching haphe's key definitions.
///
/// Duplicated here because haphe is a workspace crate and cannot be linked
/// into the `#![no_std]` kernel. The discriminant values match `haphe::input::Key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum Key {
    /// Digit 0.
    Num0 = 0,
    /// Digit 1.
    Num1 = 1,
    /// Digit 2.
    Num2 = 2,
    /// Digit 3.
    Num3 = 3,
    /// Digit 4.
    Num4 = 4,
    /// Digit 5.
    Num5 = 5,
    /// Digit 6.
    Num6 = 6,
    /// Digit 7.
    Num7 = 7,
    /// Digit 8.
    Num8 = 8,
    /// Digit 9.
    Num9 = 9,
    /// Star (*).
    Star = 10,
    /// Hash (#).
    Hash = 11,
    /// D-pad up.
    Up = 12,
    /// D-pad down.
    Down = 13,
    /// D-pad left.
    Left = 14,
    /// D-pad right.
    Right = 15,
    /// Center/OK/Select.
    Ok = 16,
    /// Left softkey.
    Lsk = 17,
    /// Right softkey.
    Rsk = 18,
    /// Call (green phone).
    Call = 19,
    /// End (red phone).
    End = 20,
    /// Power/Side button.
    Power = 21,
}

/// Input events from keypad and touchscreen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputEvent {
    /// A key was pressed.
    KeyPress(Key),
    /// A key was released.
    KeyRelease(Key),
    /// A touch at display coordinates `(x, y)`.
    Touch(u16, u16),
}

// ---------------------------------------------------------------------------
// Screen navigation
// ---------------------------------------------------------------------------

/// Screen identifiers for navigation.
///
/// Each variant maps to a concrete screen implementation. New screens added in
/// later waves extend this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScreenId {
    /// Home/idle screen.
    Home,
    /// Phone dialer.
    Dialer,
    /// Message list.
    Messages,
    /// Contact list.
    Contacts,
    /// Settings menu.
    Settings,
    /// Search.
    Search,
    /// Calendar.
    Calendar,
}

/// What the active screen wants the UI manager to do after handling input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScreenAction {
    /// No navigation change.
    None,
    /// Navigate to a different screen.
    Navigate(ScreenId),
    /// Go back to the previous screen.
    Back,
    /// Exit the UI (return to kernel idle).
    Exit,
}

/// Screen trait -- each screen implements this.
///
/// Screens render into a content-area framebuffer (`SCREEN_WIDTH * CONTENT_HEIGHT`
/// pixels of `u16` RGB565) and handle keypad input.
pub trait Screen {
    /// Draw the screen content into the content-area framebuffer.
    ///
    /// `fb` is `SCREEN_WIDTH * CONTENT_HEIGHT` pixels (64,800 u16 values).
    fn draw(&self, fb: &mut [u16]);

    /// Handle a key press. Returns the desired navigation action.
    fn on_key(&mut self, key: Key) -> ScreenAction;

    /// Label for the left softkey (bottom-left of display).
    fn softkey_left(&self) -> &'static str;

    /// Label for the right softkey (bottom-right of display).
    fn softkey_right(&self) -> &'static str;

    /// Title shown in the status bar area (empty for screens that don't need one).
    fn title(&self) -> &'static str {
        ""
    }
}

// ---------------------------------------------------------------------------
// UI manager
// ---------------------------------------------------------------------------

/// Maximum navigation history depth.
const MAX_HISTORY: usize = 16;

/// UI manager -- owns the screen stack and renders the three-zone layout.
///
/// The manager does not own screen instances directly; instead, it tracks
/// which [`ScreenId`] is active and maintains a back-navigation stack. The
/// caller is responsible for dispatching to the correct [`Screen`] impl
/// based on `active_screen()`.
pub struct UiManager {
    /// Currently active screen.
    active_screen: ScreenId,
    /// Navigation history for back navigation.
    history: Vec<ScreenId>,
}

impl UiManager {
    /// Create a new UI manager, starting at the Home screen.
    pub fn new() -> Self {
        Self {
            active_screen: ScreenId::Home,
            history: Vec::with_capacity(MAX_HISTORY),
        }
    }

    /// Return the currently active screen identifier.
    pub fn active_screen(&self) -> ScreenId {
        self.active_screen
    }

    /// Navigate to a new screen, pushing the current screen onto the
    /// back-navigation stack.
    pub fn navigate(&mut self, screen: ScreenId) {
        // Cap the history to prevent unbounded growth.
        if self.history.len() < MAX_HISTORY {
            self.history.push(self.active_screen);
        }
        self.active_screen = screen;
    }

    /// Go back to the previous screen (pop the navigation stack).
    ///
    /// If the stack is empty, stays on the current screen.
    pub fn back(&mut self) {
        if let Some(prev) = self.history.pop() {
            self.active_screen = prev;
        }
    }

    /// Return the depth of the navigation history.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Handle a [`ScreenAction`] returned by a screen's input handler.
    ///
    /// Applies the navigation action (navigate, back, or exit).
    /// Returns `true` if the UI should exit (e.g., from `ScreenAction::Exit`).
    pub fn apply_action(&mut self, action: ScreenAction) -> bool {
        match action {
            ScreenAction::None => false,
            ScreenAction::Navigate(id) => {
                self.navigate(id);
                false
            }
            ScreenAction::Back => {
                self.back();
                false
            }
            ScreenAction::Exit => true,
        }
    }

    /// Render the full three-zone display into a `SCREEN_WIDTH * SCREEN_HEIGHT`
    /// framebuffer.
    ///
    /// - `screen`: the active screen implementation
    /// - `status_bar_fn`: callback that renders the status bar into the top
    ///   `STATUS_BAR_HEIGHT` rows
    /// - `fb`: full-screen framebuffer, `SCREEN_WIDTH * SCREEN_HEIGHT` pixels
    ///
    /// WHY `&self`: the manager will use `self.active_screen` to select the
    /// screen impl once screen ownership is added (Phase 07 Wave 3+).
    #[allow(clippy::unused_self)]
    pub fn render<F>(&self, screen: &dyn Screen, status_bar_fn: F, fb: &mut [u16])
    where
        F: FnOnce(&mut [u16]),
    {
        let w = SCREEN_WIDTH as usize;

        // Zone 1: Status bar (top STATUS_BAR_HEIGHT rows).
        let status_end = w * STATUS_BAR_HEIGHT as usize;
        if let Some(status_area) = fb.get_mut(..status_end) {
            status_bar_fn(status_area);
        }

        // Zone 2: Content area (middle CONTENT_HEIGHT rows).
        let content_start = w * STATUS_BAR_HEIGHT as usize;
        let content_end = content_start + w * CONTENT_HEIGHT as usize;
        if let Some(content_area) = fb.get_mut(content_start..content_end) {
            screen.draw(content_area);
        }

        // Zone 3: Softkey bar (bottom SOFTKEY_BAR_HEIGHT rows).
        let softkey_start = w * (STATUS_BAR_HEIGHT as usize + CONTENT_HEIGHT as usize);
        if let Some(softkey_area) = fb.get_mut(softkey_start..) {
            render_softkey_bar(softkey_area, screen.softkey_left(), screen.softkey_right());
        }
    }
}

/// Render the softkey bar into a `SCREEN_WIDTH * SOFTKEY_BAR_HEIGHT` framebuffer region.
///
/// Left softkey label is left-aligned with 4px padding; right softkey label is
/// right-aligned with 4px padding.
fn render_softkey_bar(fb: &mut [u16], left_label: &str, right_label: &str) {
    let w = SCREEN_WIDTH;
    let h = SOFTKEY_BAR_HEIGHT;

    // Fill background.
    fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);

    // Draw a thin separator line at the top of the softkey bar.
    fill_rect(fb, w, h, 0, 0, w, 1, color::DARK_GREY);

    // Left label: 4px padding from left edge, vertically centered.
    let text_y = (h.saturating_sub(CHAR_HEIGHT)) / 2;
    draw_str(fb, w, 4, text_y, left_label, color::WHITE, color::BLACK);

    // Right label: 4px padding from right edge, vertically centered.
    let right_text_width = str_pixel_width(right_label);
    let right_x = w.saturating_sub(right_text_width).saturating_sub(4);
    draw_str(fb, w, right_x, text_y, right_label, color::WHITE, color::BLACK);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_dimensions_add_up() {
        assert_eq!(
            STATUS_BAR_HEIGHT + CONTENT_HEIGHT + SOFTKEY_BAR_HEIGHT,
            SCREEN_HEIGHT,
            "status bar + content + softkey bar must equal total screen height"
        );
    }

    #[test]
    fn ui_manager_starts_at_home() {
        let mgr = UiManager::new();
        assert_eq!(
            mgr.active_screen(),
            ScreenId::Home,
            "UI manager must start at the Home screen"
        );
        assert_eq!(
            mgr.history_len(),
            0,
            "initial history must be empty"
        );
    }

    #[test]
    fn navigate_pushes_history() {
        let mut mgr = UiManager::new();
        mgr.navigate(ScreenId::Dialer);
        assert_eq!(
            mgr.active_screen(),
            ScreenId::Dialer,
            "active screen must be Dialer after navigate"
        );
        assert_eq!(
            mgr.history_len(),
            1,
            "history must contain one entry after navigate"
        );
    }

    #[test]
    fn back_pops_history() {
        let mut mgr = UiManager::new();
        mgr.navigate(ScreenId::Dialer);
        mgr.navigate(ScreenId::Settings);
        assert_eq!(mgr.history_len(), 2, "history must have 2 entries");

        mgr.back();
        assert_eq!(
            mgr.active_screen(),
            ScreenId::Dialer,
            "back must return to Dialer"
        );
        assert_eq!(
            mgr.history_len(),
            1,
            "history must have 1 entry after one back"
        );

        mgr.back();
        assert_eq!(
            mgr.active_screen(),
            ScreenId::Home,
            "second back must return to Home"
        );
        assert_eq!(
            mgr.history_len(),
            0,
            "history must be empty after returning to start"
        );
    }

    #[test]
    fn back_on_empty_history_stays_at_current() {
        let mut mgr = UiManager::new();
        mgr.back();
        assert_eq!(
            mgr.active_screen(),
            ScreenId::Home,
            "back on empty history must stay at Home"
        );
    }

    #[test]
    fn apply_action_navigate_changes_screen() {
        let mut mgr = UiManager::new();
        let exit = mgr.apply_action(ScreenAction::Navigate(ScreenId::Messages));
        assert!(!exit, "Navigate must not signal exit");
        assert_eq!(mgr.active_screen(), ScreenId::Messages);
    }

    #[test]
    fn apply_action_back_returns_to_previous() {
        let mut mgr = UiManager::new();
        mgr.navigate(ScreenId::Contacts);
        let exit = mgr.apply_action(ScreenAction::Back);
        assert!(!exit, "Back must not signal exit");
        assert_eq!(mgr.active_screen(), ScreenId::Home);
    }

    #[test]
    fn apply_action_exit_signals_true() {
        let mut mgr = UiManager::new();
        let exit = mgr.apply_action(ScreenAction::Exit);
        assert!(exit, "Exit action must signal exit");
    }

    #[test]
    fn apply_action_none_does_nothing() {
        let mut mgr = UiManager::new();
        let exit = mgr.apply_action(ScreenAction::None);
        assert!(!exit, "None action must not signal exit");
        assert_eq!(mgr.active_screen(), ScreenId::Home);
    }

    #[test]
    fn key_enum_covers_all_keypad_keys() {
        // Verify all discriminant values are distinct and in range.
        let keys = [
            Key::Num0,
            Key::Num1,
            Key::Num2,
            Key::Num3,
            Key::Num4,
            Key::Num5,
            Key::Num6,
            Key::Num7,
            Key::Num8,
            Key::Num9,
            Key::Star,
            Key::Hash,
            Key::Up,
            Key::Down,
            Key::Left,
            Key::Right,
            Key::Ok,
            Key::Lsk,
            Key::Rsk,
            Key::Call,
            Key::End,
            Key::Power,
        ];
        assert_eq!(
            keys.len(),
            22,
            "Key enum must have exactly 22 variants covering the full AGM M7 keypad"
        );

        // Verify all discriminants are unique.
        let mut seen = [false; 32];
        for k in &keys {
            let disc = *k as u8;
            assert!(
                !seen[disc as usize],
                "duplicate discriminant {disc} in Key enum"
            );
            seen[disc as usize] = true;
        }
    }

    #[test]
    fn draw_str_renders_without_panic() {
        let mut fb = [0u16; 240 * 16];
        draw_str(&mut fb, 240, 0, 0, "Hello", color::WHITE, color::BLACK);
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "draw_str must produce non-zero pixels for 'Hello'");
    }

    #[test]
    fn fill_rect_clips_to_bounds() {
        let mut fb = [0u16; 10 * 10];
        // Fill that extends past bounds must not panic.
        fill_rect(&mut fb, 10, 10, 5, 5, 100, 100, color::WHITE);
        assert_eq!(fb.len(), 100, "framebuffer size must not change");
    }

    #[test]
    fn color_from_rgb_produces_correct_values() {
        assert_eq!(color::from_rgb(0, 0, 0), color::BLACK);
        assert_eq!(color::from_rgb(255, 255, 255), color::WHITE);
        assert_eq!(color::from_rgb(255, 0, 0), color::RED);
    }

    #[test]
    fn str_pixel_width_matches_char_count() {
        assert_eq!(str_pixel_width("Hello"), 40, "5 chars * 8px = 40");
        assert_eq!(str_pixel_width(""), 0, "empty string = 0 width");
    }

    #[test]
    fn render_softkey_bar_produces_pixels() {
        let mut fb = [0u16; SCREEN_WIDTH as usize * SOFTKEY_BAR_HEIGHT as usize];
        render_softkey_bar(&mut fb, "MSGS", "SEARCH");
        let any_set = fb.iter().any(|&px| px != 0);
        assert!(any_set, "softkey bar must produce visible pixels");
    }

    // Minimal Screen impl for render testing.
    struct StubScreen;

    impl Screen for StubScreen {
        fn draw(&self, fb: &mut [u16]) {
            // Fill content with a recognizable color.
            for px in fb.iter_mut() {
                *px = color::BLUE;
            }
        }
        fn on_key(&mut self, _key: Key) -> ScreenAction {
            ScreenAction::None
        }
        fn softkey_left(&self) -> &'static str {
            "LEFT"
        }
        fn softkey_right(&self) -> &'static str {
            "RIGHT"
        }
    }

    #[test]
    fn render_fills_all_three_zones() {
        let mgr = UiManager::new();
        let screen = StubScreen;
        let mut fb = [0u16; SCREEN_WIDTH as usize * SCREEN_HEIGHT as usize];

        mgr.render(
            &screen,
            |status_fb| {
                for px in status_fb.iter_mut() {
                    *px = color::RED;
                }
            },
            &mut fb,
        );

        // Status bar zone should be red.
        let status_end = SCREEN_WIDTH as usize * STATUS_BAR_HEIGHT as usize;
        assert!(
            fb[..status_end].iter().all(|&px| px == color::RED),
            "status bar zone must be filled by the status_bar_fn callback"
        );

        // Content zone should be blue (from StubScreen).
        let content_start = status_end;
        let content_end = content_start + SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize;
        assert!(
            fb[content_start..content_end].iter().all(|&px| px == color::BLUE),
            "content zone must be filled by the Screen::draw implementation"
        );

        // Softkey zone should have some non-zero pixels (text).
        let softkey_start = content_end;
        let any_softkey = fb[softkey_start..].iter().any(|&px| px != 0);
        assert!(any_softkey, "softkey zone must contain visible pixels");
    }
}
