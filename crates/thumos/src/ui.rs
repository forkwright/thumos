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
//! directly to the hardware framebuffer at `board::FB_BASE`.
//!
//! ## Font
//!
//! Text rendering uses the same 8x16 bitmap font as eidolon (`crates/eidolon/src/font.rs`).
//! The font module is duplicated here because eidolon depends on `std` (via `Vec`)
//! and cannot be linked into the `#![no_std]` kernel.

// WHY: kinit renders one initial home frame; full screen routing and input
// dispatch through UiManager are still pending.
#![expect(
    dead_code,
    reason = "UI framework has only initial home-frame kinit wiring (tier in docs/capability-inventory.toml)"
)]

extern crate alloc;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Display layout constants
// ---------------------------------------------------------------------------

/// Display width in pixels (AGM M7 QVGA).
pub(crate) const SCREEN_WIDTH: u16 = 240;

/// Display height in pixels (AGM M7 QVGA).
pub(crate) const SCREEN_HEIGHT: u16 = 320;

/// Status bar height in pixels. Fits one font row (16px) plus 4px padding.
pub(crate) const STATUS_BAR_HEIGHT: u16 = 20;

/// Softkey bar height in pixels. Fits one font row (16px) plus 14px padding.
pub(crate) const SOFTKEY_BAR_HEIGHT: u16 = 30;

/// Content area height, derived from total minus status bar and softkey bar.
pub(crate) const CONTENT_HEIGHT: u16 = SCREEN_HEIGHT - STATUS_BAR_HEIGHT - SOFTKEY_BAR_HEIGHT;

/// Y-offset where the content area begins.
pub(crate) const CONTENT_Y: u16 = STATUS_BAR_HEIGHT;

/// Content framebuffer size in pixels (width * content height).
pub(crate) const CONTENT_PIXELS: usize = SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize;

// ---------------------------------------------------------------------------
// Font constants (matching eidolon 8x16 bitmap font)
// ---------------------------------------------------------------------------

/// Width of each character cell in pixels.
pub(crate) const CHAR_WIDTH: u16 = 8;

/// Height of each character cell in pixels.
pub(crate) const CHAR_HEIGHT: u16 = 16;

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
pub(crate) mod color {
    /// Black (0x0000).
    pub(crate) const BLACK: u16 = 0x0000;
    /// White (0xFFFF).
    pub(crate) const WHITE: u16 = 0xFFFF;
    /// Red (0xF800).
    pub(crate) const RED: u16 = 0xF800;
    /// Green (0x07E0).
    pub(crate) const GREEN: u16 = 0x07E0;
    /// Blue (0x001F).
    pub(crate) const BLUE: u16 = 0x001F;
    /// Yellow (0xFFE0).
    pub(crate) const YELLOW: u16 = 0xFFE0;
    /// Dark grey for dimmed indicators.
    pub(crate) const DARK_GREY: u16 = 0x4208;

    /// Convert 24-bit RGB888 to RGB565 by truncating least significant bits.
    pub(crate) const fn from_rgb(r: u8, g: u8, b: u8) -> u16 {
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
pub(crate) fn set_pixel(fb: &mut [u16], fb_width: u16, x: u16, y: u16, color: u16) {
    let idx = y as usize * fb_width as usize + x as usize;
    if let Some(px) = fb.get_mut(idx) {
        *px = color;
    }
}

/// Fill a rectangular region in the framebuffer.
///
/// Clips to the framebuffer bounds. `fb_width` and `fb_height` define the
/// logical dimensions; `fb.len()` must equal `fb_width * fb_height`.
pub(crate) fn fill_rect(
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
pub(crate) fn draw_char(fb: &mut [u16], fb_width: u16, x: u16, y: u16, ch: char, fg: u16, bg: u16) {
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
pub(crate) fn draw_str(fb: &mut [u16], fb_width: u16, x: u16, y: u16, s: &str, fg: u16, bg: u16) {
    for (i, ch) in s.chars().enumerate() {
        let cx = x.saturating_add((i as u16).saturating_mul(CHAR_WIDTH));
        draw_char(fb, fb_width, cx, y, ch, fg, bg);
    }
}

/// Render a string horizontally centered in a region of width `region_width`,
/// starting at `region_x`.
pub(crate) fn draw_str_centered(
    fb: &mut [u16],
    fb_width: u16,
    region_x: u16,
    region_width: u16,
    y: u16,
    s: &str,
    fg: u16,
    bg: u16,
) {
    let text_width = str_pixel_width(s);
    let x = region_x.saturating_add(region_width.saturating_sub(text_width) / 2);
    draw_str(fb, fb_width, x, y, s, fg, bg);
}

/// Return the pixel width of a string rendered with this font.
///
/// WHY chars not bytes: `draw_str` renders one glyph per *character*
/// (`s.chars().enumerate()`), so the width budget must be a character
/// count -- using the UTF-8 byte length overestimates the rendered width
/// for multi-byte content (e.g., an accented contact name), mis-centering
/// or mis-aligning text that `draw_str_centered/status_bar/softkey`
/// right-alignment all depend on (#397).
pub(crate) fn str_pixel_width(s: &str) -> u16 {
    let char_count = u16::try_from(s.chars().count()).unwrap_or(u16::MAX);
    char_count.saturating_mul(CHAR_WIDTH)
}

// ---------------------------------------------------------------------------
// Scaled text rendering (shared by screen_home, screen_dialer, screen_fm,
// screen_alarm)
// ---------------------------------------------------------------------------

/// Render one character at a given scale factor.
///
/// Each font pixel becomes a `scale x scale` block. Used for large text
/// displays (clock, dialer digits, FM frequency, timer).
pub(crate) fn draw_char_scaled(
    fb: &mut [u16],
    fb_width: u16,
    x: u16,
    y: u16,
    ch: char,
    fg: u16,
    bg: u16,
    scale: u16,
) {
    let code = u32::from(ch);
    if !(FONT_FIRST..=FONT_LAST).contains(&code) {
        return;
    }
    let glyph = &FONT_DATA[(code - FONT_FIRST) as usize];
    for (row, &byte) in glyph.iter().enumerate() {
        for col in 0u16..8 {
            let bit = (byte >> (7 - col)) & 1;
            let c = if bit != 0 { fg } else { bg };
            for sy in 0..scale {
                for sx in 0..scale {
                    let px = x.saturating_add(col * scale + sx);
                    let py = y.saturating_add((row as u16) * scale + sy);
                    set_pixel(fb, fb_width, px, py, c);
                }
            }
        }
    }
}

/// Render a byte-slice string at a given scale, horizontally centered.
pub(crate) fn draw_scaled_str_centered(
    fb: &mut [u16],
    fb_width: u16,
    y: u16,
    text: &[u8],
    fg: u16,
    bg: u16,
    scale: u16,
) {
    let scaled_char_w = CHAR_WIDTH * scale;
    let text_width = text.len() as u16 * scaled_char_w;
    let x_start = fb_width.saturating_sub(text_width) / 2;

    for (i, &byte) in text.iter().enumerate() {
        let ch = byte as char;
        let x = x_start.saturating_add(i as u16 * scaled_char_w);
        draw_char_scaled(fb, fb_width, x, y, ch, fg, bg, scale);
    }
}

// ---------------------------------------------------------------------------
// Input event types (kernel-side, mirroring haphe::input::Key)
// ---------------------------------------------------------------------------

/// Key codes for the kernel-side input path.
///
/// Duplicated here because haphe is a workspace crate and cannot be linked
/// into the `#![no_std]` kernel's shipped (armv7a) target. Only the digit /
/// star / hash / d-pad prefix (`Num0..=Right`, discriminants 0-15) is a
/// genuine shared vocabulary with `haphe::input::Key` — the same physical
/// matrix keys, pinned equal by the `shared_prefix_discriminants_match_haphe`
/// test below (checked against the real `haphe` crate, not a copied
/// constant). The extended range (16-21, `Ok`/`Lsk`/`Rsk`/`Call`/`End`/
/// `Power`) is this enum's OWN vocabulary and is NOT required to match
/// haphe's `Select`/`Call`/`End`/`Side`/`VolUp`/`VolDown` at the same
/// discriminants — the two enums model different button sets above the
/// matrix (this one has softkeys; haphe's has the volume rocker and side
/// button instead), so a numeric cast between them for 16+ would silently
/// mis-map keys (#615). A future userspace-to-kernel input bridge MUST
/// convert through an explicit, exhaustive `match`, never a bare `as` cast,
/// across this whole enum.
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
    /// Function search ("everything launcher").
    Search,
    /// Calendar.
    Calendar,
    /// Active/incoming voice call.
    InCall,
    /// Timer.
    Timer,
    /// Stopwatch.
    Stopwatch,
    /// Alarms.
    Alarms,
    /// FM Radio.
    FmRadio,
    /// `WiFi` settings (read-only display of wifi state).
    WifiSettings,
    /// Bluetooth settings (read-only display of BT state).
    BtSettings,
    /// Privacy settings.
    Privacy,
    /// Radio control panel (COVERT LOCK / STEALTH / RESTORE).
    RadioControl,
    /// About screen (device info, OS version).
    About,
    /// Battery status screen.
    Battery,
    /// Nous chat screen (AI entity conversation).
    Nous,
    /// Threat monitor (centralized radio intelligence dashboard).
    ThreatMonitor,
}

/// Human-readable name for a `ScreenId`. SSOT for screen naming: the
/// not-implemented placeholder screen (`screen_unimplemented.rs`) uses this
/// to name the screen it is standing in for, and the qemu navigation CI
/// witness (`kardia.rs`) uses it to label the `from`/`to` screens in its
/// marker line.
///
/// Exhaustive over `ScreenId` with NO catch-all: adding a variant without a
/// label here is a compile error, so a screen can never go silently
/// unnamed (#730).
pub(crate) const fn screen_label(id: ScreenId) -> &'static str {
    match id {
        ScreenId::Home => "Home",
        ScreenId::Dialer => "Dialer",
        ScreenId::Messages => "Messages",
        ScreenId::Contacts => "Contacts",
        ScreenId::Settings => "Settings",
        ScreenId::Search => "Search",
        ScreenId::Calendar => "Calendar",
        ScreenId::InCall => "In Call",
        ScreenId::Timer => "Timer",
        ScreenId::Stopwatch => "Stopwatch",
        ScreenId::Alarms => "Alarms",
        ScreenId::FmRadio => "FM Radio",
        ScreenId::WifiSettings => "WiFi Settings",
        ScreenId::BtSettings => "Bluetooth Settings",
        ScreenId::Privacy => "Privacy",
        ScreenId::RadioControl => "Radio Control",
        ScreenId::About => "About",
        ScreenId::Battery => "Battery",
        ScreenId::Nous => "Nous",
        ScreenId::ThreatMonitor => "Threat Monitor",
    }
}

/// Which concrete screen family a `ScreenId` maps to -- the SINGLE
/// classification table `kardia.rs`'s `KernelState::active_screen_mut`
/// (input dispatch) and `KernelState::render_if_dirty` (render dispatch)
/// both match on, so the two dispatches can no longer drift apart
/// independently. That drift is exactly what #730 found: `FmRadio` was in
/// the input match's arm list but missing from the render match's, so the
/// FM screen took every keypress while the framebuffer kept showing Home,
/// and twelve `screen_search.rs` entries had no render arm at all, silently
/// painting Home when selected.
///
/// Lives here (not in `kardia.rs`) because `kardia`'s `mod` declaration is
/// `#[cfg(not(test))]` (it is the runtime continuation of the hardware boot
/// path, #420/#528) -- classification logic that must itself be
/// host-testable cannot live inside a module the host test build never
/// compiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScreenKind {
    /// Home/idle screen.
    Home,
    /// Message list.
    Messages,
    /// Function search ("everything launcher").
    Search,
    /// Phone dialer.
    Dialer,
    /// Settings menu.
    Settings,
    /// Calendar.
    Calendar,
    /// FM Radio.
    FmRadio,
    /// Privacy dashboard.
    Privacy,
    /// Radio control panel.
    RadioControl,
    /// Threat monitor.
    ThreatMonitor,
    /// No screen is wired into `KernelState` for this `ScreenId` yet. Both
    /// dispatches route this to the not-implemented placeholder screen
    /// (`screen_unimplemented.rs`), which renders an unmistakable state
    /// naming the requested screen -- never Home.
    NotImplemented,
}

/// Classify a `ScreenId` into its [`ScreenKind`] (#730).
///
/// Exhaustive over `ScreenId` with NO catch-all: adding a `ScreenId`
/// variant fails this match at compile time until it is classified here,
/// which then fails BOTH of `kardia.rs`'s dispatches at compile time (their
/// matches over `ScreenKind` have no catch-all either) until each handles
/// the new kind. That double exhaustiveness is the property the issue
/// asked for: the divergence between the two dispatches is now a compile
/// error, not a silent runtime fallback.
pub(crate) fn screen_kind(id: ScreenId) -> ScreenKind {
    match id {
        ScreenId::Home => ScreenKind::Home,
        ScreenId::Messages => ScreenKind::Messages,
        ScreenId::Search => ScreenKind::Search,
        ScreenId::Dialer => ScreenKind::Dialer,
        ScreenId::Settings => ScreenKind::Settings,
        ScreenId::Calendar => ScreenKind::Calendar,
        ScreenId::FmRadio => ScreenKind::FmRadio,
        ScreenId::Privacy => ScreenKind::Privacy,
        ScreenId::RadioControl => ScreenKind::RadioControl,
        ScreenId::ThreatMonitor => ScreenKind::ThreatMonitor,
        // Compiled screens with no route into KernelState yet (#737 tracks
        // wiring each in): Alarms/Timer/Stopwatch (screen_alarm.rs),
        // InCall (screen_call.rs), Contacts (screen_contacts.rs),
        // Nous (screen_nous.rs), WifiSettings/BtSettings/About
        // (screen_settings.rs). Battery has no screen implementation at
        // all yet.
        ScreenId::Contacts
        | ScreenId::InCall
        | ScreenId::Timer
        | ScreenId::Stopwatch
        | ScreenId::Alarms
        | ScreenId::WifiSettings
        | ScreenId::BtSettings
        | ScreenId::About
        | ScreenId::Battery
        | ScreenId::Nous => ScreenKind::NotImplemented,
    }
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
    /// Trigger modem PMIC power cut (emergency kill).
    KillModem,
    /// Duress authentication detected — start the silent panic/wipe sequence.
    /// The unlock looks normal on screen; this is the only navigation-channel
    /// signal that carries the duress event to the privileged event loop.
    Duress,
}

/// Screen trait -- each screen implements this.
///
/// Screens render into a content-area framebuffer (`SCREEN_WIDTH * CONTENT_HEIGHT`
/// pixels of `u16` RGB565) and handle keypad input.
pub(crate) trait Screen {
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
pub(crate) struct UiManager {
    /// Currently active screen.
    active_screen: ScreenId,
    /// Navigation history for back navigation.
    history: Vec<ScreenId>,
}

impl UiManager {
    /// Create a new UI manager, starting at the Home screen.
    pub(crate) fn new() -> Self {
        Self {
            active_screen: ScreenId::Home,
            history: Vec::with_capacity(MAX_HISTORY),
        }
    }

    /// Return the currently active screen identifier.
    pub(crate) fn active_screen(&self) -> ScreenId {
        self.active_screen
    }

    /// Navigate to a new screen, pushing the current screen onto the
    /// back-navigation stack.
    pub(crate) fn navigate(&mut self, screen: ScreenId) {
        // WHY: drop the OLDEST entry (not the newest) once history is
        // full. Previously, once MAX_HISTORY was reached, the push below
        // was skipped entirely while the navigation still proceeded --
        // so the screen being navigated FROM was never recorded, and a
        // subsequent back() skipped past it to a stale, no-longer-
        // adjacent screen. Shifting out the oldest entry keeps back()
        // always returning to the immediately-previous screen; only the
        // tail of very old history is bounded away.
        if self.history.len() >= MAX_HISTORY {
            self.history.remove(0);
        }
        self.history.push(self.active_screen);
        self.active_screen = screen;
    }

    /// Go back to the previous screen (pop the navigation stack).
    ///
    /// If the stack is empty, stays on the current screen.
    pub(crate) fn back(&mut self) {
        if let Some(prev) = self.history.pop() {
            self.active_screen = prev;
        }
    }

    /// Return the depth of the navigation history.
    pub(crate) fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Handle a [`ScreenAction`] returned by a screen's input handler.
    ///
    /// Applies the navigation action (navigate, back, or exit).
    /// Returns `true` if the UI should exit (e.g., from `ScreenAction::Exit`).
    // WHY: Exit, KillModem, and Duress all return true, but each does so for
    // a different reason (documented per-arm below: real UI exit vs. a
    // privileged hardware action vs. yielding to the panic sequence).
    // Merging them into one arm would blur those distinct rationales.
    #[expect(
        clippy::match_same_arms,
        reason = "Exit, KillModem, and Duress all return true for different reasons -- real UI exit vs. a privileged hardware action vs. yielding to the panic sequence; merging would blur those distinct rationales"
    )]
    pub(crate) fn apply_action(&mut self, action: ScreenAction) -> bool {
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
            // WHY: KillModem is a hardware action dispatched by the kernel
            // event loop, not a navigation action. The UI manager signals
            // it upward by returning true (same as Exit) so the caller can
            // execute the PMIC power cut in privileged context.
            ScreenAction::KillModem => true,
            // WHY: Duress, like KillModem, is a privileged action the kernel
            // event loop executes (start panic/wipe) in privileged context.
            // The loop inspects the returned ScreenAction and branches on
            // Duress before applying it; apply_action returns true so the UI
            // yields to the panic sequence.
            ScreenAction::Duress => true,
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
    #[expect(
        clippy::unused_self,
        reason = "Screen trait requires &self for future state access"
    )]
    pub(crate) fn render<F>(&self, screen: &dyn Screen, status_bar_fn: F, fb: &mut [u16])
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
    draw_str(
        fb,
        w,
        right_x,
        text_y,
        right_label,
        color::WHITE,
        color::BLACK,
    );
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
        assert_eq!(mgr.history_len(), 0, "initial history must be empty");
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
    fn navigate_past_max_history_drops_oldest_not_newest() {
        let mut mgr = UiManager::new();
        let screens = [
            ScreenId::Dialer,
            ScreenId::Messages,
            ScreenId::Contacts,
            ScreenId::Settings,
            ScreenId::Search,
            ScreenId::Calendar,
            ScreenId::InCall,
            ScreenId::Timer,
            ScreenId::Stopwatch,
            ScreenId::Alarms,
            ScreenId::FmRadio,
            ScreenId::WifiSettings,
            ScreenId::BtSettings,
            ScreenId::Privacy,
            ScreenId::RadioControl,
            ScreenId::About,
            ScreenId::Battery, // 17th navigate -- overflows MAX_HISTORY (16)
        ];
        for &s in &screens {
            mgr.navigate(s);
        }

        assert_eq!(
            mgr.history_len(),
            MAX_HISTORY,
            "history must stay capped at MAX_HISTORY, not grow unbounded"
        );

        // The screen immediately before the last navigate (About) must
        // still be what back() returns to -- not a stale entry from
        // before the overflow.
        mgr.back();
        assert_eq!(
            mgr.active_screen(),
            ScreenId::About,
            "back() after overflowing history must return to the \
             immediately-previous screen, not skip past it"
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

    /// Pins the ONLY genuine shared-vocabulary claim between `ui::Key` and
    /// `haphe::input::Key`: the digit / star / hash / d-pad prefix
    /// (discriminants 0-15) is the same physical matrix keys with the same
    /// meaning in both enums, so a boot-path value can round-trip through
    /// the raw `u8` without a lookup table. This imports the REAL `haphe`
    /// crate (see Cargo.toml `[dev-dependencies]`, #615) rather than a
    /// copied constant, so a discriminant change on EITHER side breaks this
    /// test -- the two enums cannot drift apart silently again.
    ///
    /// Deliberately does NOT extend to 16-21: `ui::Key`'s `Ok`/`Lsk`/`Rsk`/
    /// `Call`/`End`/`Power` and haphe's `Select`/`Call`/`End`/`Side`/
    /// `VolUp`/`VolDown` are different button sets that happen to share a
    /// numeric range -- they are NOT required to align (see the doc comment
    /// on `Key` above).
    #[test]
    fn shared_prefix_discriminants_match_haphe() {
        let pairs: [(Key, haphe::input::Key); 16] = [
            (Key::Num0, haphe::input::Key::Num0),
            (Key::Num1, haphe::input::Key::Num1),
            (Key::Num2, haphe::input::Key::Num2),
            (Key::Num3, haphe::input::Key::Num3),
            (Key::Num4, haphe::input::Key::Num4),
            (Key::Num5, haphe::input::Key::Num5),
            (Key::Num6, haphe::input::Key::Num6),
            (Key::Num7, haphe::input::Key::Num7),
            (Key::Num8, haphe::input::Key::Num8),
            (Key::Num9, haphe::input::Key::Num9),
            (Key::Star, haphe::input::Key::Star),
            (Key::Hash, haphe::input::Key::Hash),
            (Key::Up, haphe::input::Key::Up),
            (Key::Down, haphe::input::Key::Down),
            (Key::Left, haphe::input::Key::Left),
            (Key::Right, haphe::input::Key::Right),
        ];
        for (ui_key, haphe_key) in pairs {
            assert_eq!(
                ui_key as u8, haphe_key as u8,
                "ui::Key::{ui_key:?} discriminant must match \
                 haphe::input::Key::{haphe_key:?} -- both encode the same \
                 physical matrix key"
            );
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
    fn draw_char_silently_skips_non_ascii_without_panicking() {
        // draw_char intentionally has no glyph for codepoints outside the
        // printable-ASCII font table (FONT_FIRST..=FONT_LAST, 0x20..=0x7E)
        // -- FONT_DATA only covers that range. Pin the documented
        // behavior: an out-of-range codepoint (e.g., U+00E9) is silently
        // skipped (no panic, no pixels touched), rather than panicking on
        // an out-of-bounds FONT_DATA index (#397, info).
        let mut fb = [0u16; 8 * 16];
        draw_char(&mut fb, 8, 0, 0, '\u{00e9}', color::WHITE, color::BLACK);
        assert!(
            fb.iter().all(|&px| px == 0),
            "an out-of-font-range codepoint must leave the framebuffer \
             untouched, not panic"
        );

        // A codepoint within range still renders normally.
        let mut fb2 = [0u16; 8 * 16];
        draw_char(&mut fb2, 8, 0, 0, 'A', color::WHITE, color::BLACK);
        assert!(
            fb2.iter().any(|&px| px != 0),
            "an in-range ASCII codepoint must still render"
        );
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
    fn str_pixel_width_counts_chars_not_bytes_for_multibyte_utf8() {
        // 4 characters, the last a 2-byte codepoint -- 5 UTF-8 bytes
        // total. A byte-length-based width overestimates by one
        // CHAR_WIDTH, mis-centering any string with multi-byte content
        // (#397).
        assert_eq!(
            str_pixel_width("caf\u{00e9}"),
            4 * CHAR_WIDTH,
            "width must reflect 4 characters, not 5 UTF-8 bytes"
        );
    }

    #[test]
    fn draw_str_centered_centers_by_char_count_for_multibyte_utf8() {
        // Regression for #397: draw_str_centered previously used the
        // UTF-8 byte length to compute centering, which would shift a
        // multi-byte string off-center relative to an equal-character
        // ASCII string.
        let mut fb_multibyte = [0u16; 240 * 16];
        draw_str_centered(
            &mut fb_multibyte,
            240,
            0,
            240,
            0,
            "caf\u{00e9}",
            color::WHITE,
            color::BLACK,
        );

        let mut fb_ascii = [0u16; 240 * 16];
        draw_str_centered(
            &mut fb_ascii,
            240,
            0,
            240,
            0,
            "cafe",
            color::WHITE,
            color::BLACK,
        );

        // Both are 4 characters, so both must start at the same column --
        // find the first set pixel column in each and compare.
        let first_set_col = |fb: &[u16]| -> Option<usize> {
            (0..240).find(|&x| (0..16).any(|y| fb[y * 240 + x] != 0))
        };
        assert_eq!(
            first_set_col(&fb_multibyte),
            first_set_col(&fb_ascii),
            "a 4-char multi-byte string must center identically to a \
             4-char ASCII string"
        );
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
        let mut fb = alloc::vec![0u16; SCREEN_WIDTH as usize * SCREEN_HEIGHT as usize];

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
            fb[content_start..content_end]
                .iter()
                .all(|&px| px == color::BLUE),
            "content zone must be filled by the Screen::draw implementation"
        );

        // Softkey zone should have some non-zero pixels (text).
        let softkey_start = content_end;
        let any_softkey = fb[softkey_start..].iter().any(|&px| px != 0);
        assert!(any_softkey, "softkey zone must contain visible pixels");
    }

    /// #730: every `ScreenId` with no wired screen must classify as
    /// `NotImplemented`, never as `Home` -- the exact defect this
    /// classifier exists to make impossible (`FmRadio` input-wired/
    /// render-missing, plus the twelve `screen_search.rs` entries with no
    /// render arm at all, all fell through to the render match's old
    /// `_ => &self.home` catch-all).
    #[test]
    fn unwired_screens_are_not_implemented_not_home() {
        const UNWIRED: [ScreenId; 10] = [
            ScreenId::Contacts,
            ScreenId::InCall,
            ScreenId::Timer,
            ScreenId::Stopwatch,
            ScreenId::Alarms,
            ScreenId::WifiSettings,
            ScreenId::BtSettings,
            ScreenId::About,
            ScreenId::Battery,
            ScreenId::Nous,
        ];
        for id in UNWIRED {
            let kind = screen_kind(id);
            assert_eq!(
                kind,
                ScreenKind::NotImplemented,
                "{id:?} has no wired screen; it must classify as NotImplemented rather than fall through to Home"
            );
            assert_ne!(
                kind,
                ScreenKind::Home,
                "{id:?} must never be silently indistinguishable from Home (#730)"
            );
        }
    }

    /// Every screen genuinely wired into `KernelState` keeps its own,
    /// distinct classification. This is the SSOT both of `kardia.rs`'s
    /// dispatches derive from, so a wired screen accidentally grouped into
    /// the not-implemented arm list -- or `FmRadio`'s #730 regression in
    /// reverse -- is caught here.
    #[test]
    fn wired_screens_keep_distinct_classification() {
        const WIRED: [(ScreenId, ScreenKind); 7] = [
            (ScreenId::Home, ScreenKind::Home),
            (ScreenId::Messages, ScreenKind::Messages),
            (ScreenId::Search, ScreenKind::Search),
            (ScreenId::Dialer, ScreenKind::Dialer),
            (ScreenId::Settings, ScreenKind::Settings),
            (ScreenId::Calendar, ScreenKind::Calendar),
            (ScreenId::FmRadio, ScreenKind::FmRadio),
        ];
        for (id, expect) in WIRED {
            assert_eq!(screen_kind(id), expect, "{id:?} classification drifted");
        }
    }
}
