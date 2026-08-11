//! Not-implemented placeholder screen for the thumos kernel UI.
//!
//! `kardia.rs`'s input and render dispatches are exhaustive over
//! `ScreenId` with no catch-all arm (#730): every `ScreenId` maps to either
//! a real wired screen or this placeholder. A screen with no wired
//! implementation therefore renders an unmistakable "NOT IMPLEMENTED"
//! state naming itself, instead of silently falling through to Home --
//! the fail-open shape #730 fixed (a user who opened Threat Monitor and
//! saw Home would read that as "checked, nothing to report", not
//! "unimplemented").

use crate::ui::{
    self, CHAR_HEIGHT, CONTENT_HEIGHT, Key, SCREEN_WIDTH, Screen, ScreenAction, ScreenId, color,
};

/// Border thickness (px) framing the placeholder. Part of what makes the
/// state unmistakable at a glance, distinct from every real screen's
/// content (none of which draws a full-frame colored border).
const BORDER_PX: u16 = 3;

/// Fallback screen for a `ScreenId` the kernel dispatch does not yet
/// render.
///
/// INVARIANT: this is the ONLY fallback in `kardia.rs`'s render/input
/// dispatches -- `kardia::screen_kind` routes every unhandled `ScreenId`
/// here rather than to Home (#730). `kardia.rs` calls [`Self::set_screen`]
/// with the current `ScreenId` before every dispatch, so the label always
/// names whichever screen is actually active, not whichever was active
/// when the placeholder was constructed.
pub(crate) struct UnimplementedScreen {
    /// The screen this stand-in currently represents.
    id: ScreenId,
}

impl UnimplementedScreen {
    /// Construct with an arbitrary initial id; `kardia.rs` overwrites it via
    /// [`Self::set_screen`] before every render/input dispatch.
    pub(crate) fn new() -> Self {
        Self { id: ScreenId::Home }
    }

    /// Record which screen this stand-in is currently representing.
    pub(crate) fn set_screen(&mut self, id: ScreenId) {
        self.id = id;
    }
}

impl Screen for UnimplementedScreen {
    fn draw(&self, fb: &mut [u16]) {
        let w = SCREEN_WIDTH;
        let h = CONTENT_HEIGHT;
        ui::fill_rect(fb, w, h, 0, 0, w, h, color::BLACK);
        // Full-frame red border -- no real screen draws one, so this state
        // reads as distinct even before the text is legible.
        ui::fill_rect(fb, w, h, 0, 0, w, BORDER_PX, color::RED);
        ui::fill_rect(fb, w, h, 0, h - BORDER_PX, w, BORDER_PX, color::RED);
        ui::fill_rect(fb, w, h, 0, 0, BORDER_PX, h, color::RED);
        ui::fill_rect(fb, w, h, w - BORDER_PX, 0, BORDER_PX, h, color::RED);
        ui::draw_str_centered(
            fb,
            w,
            0,
            w,
            h / 2 - CHAR_HEIGHT,
            "NOT IMPLEMENTED",
            color::RED,
            color::BLACK,
        );
        ui::draw_str_centered(
            fb,
            w,
            0,
            w,
            h / 2 + 4,
            ui::screen_label(self.id),
            color::WHITE,
            color::BLACK,
        );
    }

    fn on_key(&mut self, key: Key) -> ScreenAction {
        if matches!(key, Key::Rsk | Key::End) {
            ScreenAction::Back
        } else {
            ScreenAction::None
        }
    }

    fn softkey_left(&self) -> &'static str {
        ""
    }

    fn softkey_right(&self) -> &'static str {
        "BACK"
    }

    fn title(&self) -> &'static str {
        "Not Implemented"
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// Every `ScreenId` this screen might be asked to stand in for, so the
    /// tests below cover the whole enum rather than one hand-picked example.
    const ALL_SCREEN_IDS: [ScreenId; 20] = [
        ScreenId::Home,
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
        ScreenId::Battery,
        ScreenId::Nous,
        ScreenId::ThreatMonitor,
    ];

    #[test]
    fn draw_renders_visible_content_for_every_screen_id() {
        for id in ALL_SCREEN_IDS {
            let mut screen = UnimplementedScreen::new();
            screen.set_screen(id);
            let mut fb = alloc::vec![0u16; SCREEN_WIDTH as usize * CONTENT_HEIGHT as usize];
            screen.draw(&mut fb);
            assert!(
                fb.iter().any(|&px| px != 0),
                "{id:?} not-implemented render must paint visible content, not stay blank"
            );
        }
    }

    #[test]
    fn on_key_back_returns_to_previous_screen() {
        let mut screen = UnimplementedScreen::new();
        assert_eq!(screen.on_key(Key::Rsk), ScreenAction::Back);
        assert_eq!(screen.on_key(Key::End), ScreenAction::Back);
    }

    #[test]
    fn on_key_other_keys_do_not_navigate() {
        let mut screen = UnimplementedScreen::new();
        assert_eq!(screen.on_key(Key::Ok), ScreenAction::None);
    }

    #[test]
    fn screen_label_is_distinct_and_nonempty_per_id() {
        // A collision would let two different not-implemented screens read
        // as the same one; an empty label would render as a blank second
        // line, undermining the "must name the screen" requirement (#730).
        let mut seen: Vec<&str> = Vec::new();
        for id in ALL_SCREEN_IDS {
            let label = ui::screen_label(id);
            assert!(!label.is_empty(), "{id:?} has an empty label");
            assert!(!seen.contains(&label), "label '{label}' reused for {id:?}");
            seen.push(label);
        }
    }
}
