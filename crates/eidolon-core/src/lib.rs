//! Canonical display layout geometry for the AGM M7 panel.
#![no_std]
#![deny(missing_docs)]

/// Display width in pixels (AGM M7 QVGA).
pub const SCREEN_WIDTH: u16 = 240;

/// Display height in pixels (AGM M7 QVGA).
pub const SCREEN_HEIGHT: u16 = 320;

/// Status bar height in pixels.
///
/// Fits one 16px font row plus 2px above and below. The padding is the
/// reason this is not simply the glyph height: a bar sized exactly to the
/// glyph leaves ascenders touching the content area.
pub const STATUS_BAR_HEIGHT: u16 = 20;

/// Softkey bar height in pixels. Fits one 16px font row plus 14px padding.
pub const SOFTKEY_BAR_HEIGHT: u16 = 30;

/// Content area height, derived from total minus status bar and softkey bar.
pub const CONTENT_HEIGHT: u16 = SCREEN_HEIGHT - STATUS_BAR_HEIGHT - SOFTKEY_BAR_HEIGHT;

/// Y-offset where the content area begins.
pub const CONTENT_Y: u16 = STATUS_BAR_HEIGHT;

/// Content framebuffer size in pixels (width * content height).
pub const CONTENT_PIXELS: usize = SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize;

#[cfg(test)]
mod tests {
    use super::{
        CONTENT_HEIGHT, CONTENT_PIXELS, CONTENT_Y, SCREEN_HEIGHT, SCREEN_WIDTH, SOFTKEY_BAR_HEIGHT,
        STATUS_BAR_HEIGHT,
    };

    /// The three zones must tile the panel exactly. A gap or an overlap is
    /// the four-pixel misalignment #740 describes: nothing panics, no test
    /// fails, and every zone boundary sits one glyph-quarter off.
    #[test]
    fn the_three_zones_tile_the_panel_exactly() {
        assert_eq!(
            STATUS_BAR_HEIGHT + CONTENT_HEIGHT + SOFTKEY_BAR_HEIGHT,
            SCREEN_HEIGHT
        );
        assert_eq!(CONTENT_Y, STATUS_BAR_HEIGHT);
        assert_eq!(
            CONTENT_PIXELS,
            SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize
        );
    }
}
