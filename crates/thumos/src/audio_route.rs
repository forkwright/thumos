//! Audio route arbitration for the phthongos audio subsystem.
//!
//! Manages the set of connected audio output devices and determines the
//! correct output route for each session kind.  Handles hot-plug events
//! (Bluetooth connect/disconnect, wired headset connect/disconnect) and
//! speakerphone toggling during voice calls.
//!
//! ## Routing priority (per design-phthongos.md)
//!
//! 1. USB DAC connected and session requests `UsbDac` or `BitPerfect` -> USB
//! 2. BT audio device paired and active -> BT (A2DP for music)
//! 3. User toggled speakerphone -> loudspeaker
//! 4. Calls -> earpiece
//! 5. Everything else (ringtones, alarms, music, FM) -> loudspeaker
//!
//! ## Native headset boundary on M7
//!
//! Repository evidence does not establish whether the AGM M7 exposes a native
//! 3.5mm jack; ACCDET driver presence alone is not physical proof. The
//! `Headset` route therefore exists but is never auto-selected on the M7. A
//! USB-C audio adapter appears separately as `UsbDac`.
//!
//! ## Integration
//!
//! Used by [`super::audio::AudioManager`] to determine the default route
//! when opening a session and to react to peripheral connect/disconnect.

// WHY: kardia owns RouteManager and QEMU exercises its mock route state; some
// producer/hot-plug paths remain unused in production.
#![expect(
    dead_code,
    reason = "Audio routing is service-loop wired; unused producer/hot-plug paths remain #753"
)]

extern crate alloc;
use alloc::vec::Vec;

use super::audio_codec::AudioError;

// ---------------------------------------------------------------------------
// Audio route enumeration
// ---------------------------------------------------------------------------

/// Audio output route.
///
/// Determines which physical output path carries the audio signal.
/// The codec and amplifier configuration differ per route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AudioRoute {
    /// Front earpiece receiver — voice calls held to ear.
    Earpiece,
    /// Rear loudspeaker — ringtones, alarms, music, speakerphone.
    Speaker,
    /// Bluetooth A2DP (stereo music) or HFP (calls, future).
    BluetoothA2dp,
    /// External USB DAC via USB-C (requires USB host mode).
    UsbDac,
    /// Wired headset via USB-C adapter (appears as USB audio device).
    ///
    /// Native M7 availability is unverified; never auto-selected by default.
    Headset,
}

impl core::fmt::Display for AudioRoute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Earpiece => write!(f, "earpiece"),
            Self::Speaker => write!(f, "speaker"),
            Self::BluetoothA2dp => write!(f, "bluetooth"),
            Self::UsbDac => write!(f, "USB DAC"),
            Self::Headset => write!(f, "headset"),
        }
    }
}

// ---------------------------------------------------------------------------
// Session kind (shared with audio.rs)
// ---------------------------------------------------------------------------

/// Audio session kind.
///
/// Each kind has a default priority and default output route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionKind {
    /// Duplex voice call (cellular or `VoIP`).
    VoiceCall,
    /// Incoming call ringtone.
    Ringtone,
    /// Music playback (standard quality).
    Music,
    /// Alarm or timer alert.
    Alarm,
    /// Short notification sound.
    Notification,
    /// FM radio receiver output.
    FmRadio,
}

impl core::fmt::Display for SessionKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VoiceCall => write!(f, "voice call"),
            Self::Ringtone => write!(f, "ringtone"),
            Self::Music => write!(f, "music"),
            Self::Alarm => write!(f, "alarm"),
            Self::Notification => write!(f, "notification"),
            Self::FmRadio => write!(f, "FM radio"),
        }
    }
}

// ---------------------------------------------------------------------------
// Route manager
// ---------------------------------------------------------------------------

/// Audio route arbitration manager.
///
/// Tracks connected output devices and determines the correct route for
/// each session kind based on priority rules and user preferences.
pub(crate) struct RouteManager {
    /// Currently connected/available output devices.
    connected_outputs: Vec<AudioRoute>,
    /// Preferred route for voice calls (default: earpiece).
    preferred_call_route: AudioRoute,
    /// Preferred route for media playback (default: speaker).
    preferred_media_route: AudioRoute,
    /// Whether speakerphone is currently toggled on.
    speakerphone_active: bool,
}

impl RouteManager {
    /// Create a new route manager with default preferences.
    ///
    /// The earpiece and speaker are always connected (built-in).
    #[must_use]
    pub(crate) fn new() -> Self {
        let mut connected = Vec::with_capacity(4);
        // Built-in outputs are always available.
        connected.push(AudioRoute::Earpiece);
        connected.push(AudioRoute::Speaker);

        Self {
            connected_outputs: connected,
            preferred_call_route: AudioRoute::Earpiece,
            preferred_media_route: AudioRoute::Speaker,
            speakerphone_active: false,
        }
    }

    /// Return the default audio route for a given session kind.
    ///
    /// Applies the routing priority rules from the design doc:
    /// - Voice calls: earpiece (or speaker if speakerphone toggled)
    /// - Ringtone, alarm, notification: speaker
    /// - Music: speaker (or BT/USB DAC if connected)
    /// - FM radio: speaker
    #[must_use]
    pub(crate) fn default_route_for(&self, kind: SessionKind) -> AudioRoute {
        match kind {
            SessionKind::VoiceCall => {
                if self.speakerphone_active {
                    AudioRoute::Speaker
                } else {
                    self.preferred_call_route
                }
            }
            SessionKind::Music => {
                // Prefer USB DAC, then BT, then speaker.
                if self.is_output_available(AudioRoute::UsbDac) {
                    return AudioRoute::UsbDac;
                }
                if self.is_output_available(AudioRoute::BluetoothA2dp) {
                    return AudioRoute::BluetoothA2dp;
                }
                self.preferred_media_route
            }
            SessionKind::Ringtone
            | SessionKind::Alarm
            | SessionKind::Notification
            | SessionKind::FmRadio => AudioRoute::Speaker,
        }
    }

    /// Toggle speakerphone for voice calls.
    ///
    /// When toggled on, call audio routes to the loudspeaker instead of
    /// the earpiece.  Toggling again reverts to earpiece.
    ///
    /// Returns the new route that should be applied to the active call.
    #[must_use]
    pub(crate) fn toggle_speakerphone(&mut self) -> AudioRoute {
        self.speakerphone_active = !self.speakerphone_active;
        if self.speakerphone_active {
            AudioRoute::Speaker
        } else {
            self.preferred_call_route
        }
    }

    /// Check whether a specific output route is currently available.
    #[must_use]
    pub(crate) fn is_output_available(&self, route: AudioRoute) -> bool {
        self.connected_outputs.contains(&route)
    }

    /// Return a slice of all currently connected outputs.
    #[must_use]
    pub(crate) fn connected_outputs(&self) -> &[AudioRoute] {
        &self.connected_outputs
    }

    /// Return whether speakerphone is currently active.
    #[must_use]
    pub(crate) fn is_speakerphone_active(&self) -> bool {
        self.speakerphone_active
    }

    // -----------------------------------------------------------------------
    // Hot-plug event handlers
    // -----------------------------------------------------------------------

    /// Notify that a Bluetooth audio device has connected.
    ///
    /// Adds `BluetoothA2dp` to the available outputs if not already present.
    pub(crate) fn notify_bt_connected(&mut self) {
        if !self.is_output_available(AudioRoute::BluetoothA2dp) {
            self.connected_outputs.push(AudioRoute::BluetoothA2dp);
        }
    }

    /// Notify that a Bluetooth audio device has disconnected.
    ///
    /// Removes `BluetoothA2dp` from the available outputs.
    pub(crate) fn notify_bt_disconnected(&mut self) {
        self.connected_outputs
            .retain(|r| *r != AudioRoute::BluetoothA2dp);
    }

    /// Notify that a wired headset has connected (via USB-C adapter).
    ///
    /// Adds `Headset` to the available outputs if not already present.
    pub(crate) fn notify_headset_connected(&mut self) {
        if !self.is_output_available(AudioRoute::Headset) {
            self.connected_outputs.push(AudioRoute::Headset);
        }
    }

    /// Notify that a wired headset has disconnected.
    ///
    /// Removes `Headset` from the available outputs.
    pub(crate) fn notify_headset_disconnected(&mut self) {
        self.connected_outputs.retain(|r| *r != AudioRoute::Headset);
    }

    /// Notify that a USB DAC has connected.
    ///
    /// Adds `UsbDac` to the available outputs if not already present.
    pub(crate) fn notify_usb_dac_connected(&mut self) {
        if !self.is_output_available(AudioRoute::UsbDac) {
            self.connected_outputs.push(AudioRoute::UsbDac);
        }
    }

    /// Notify that a USB DAC has disconnected.
    ///
    /// Removes `UsbDac` from the available outputs.
    pub(crate) fn notify_usb_dac_disconnected(&mut self) {
        self.connected_outputs.retain(|r| *r != AudioRoute::UsbDac);
    }

    /// Set the preferred call route (for when a BT headset is the
    /// default call device, for example).
    pub(crate) fn set_preferred_call_route(&mut self, route: AudioRoute) {
        self.preferred_call_route = route;
    }

    /// Set the preferred media route.
    pub(crate) fn set_preferred_media_route(&mut self, route: AudioRoute) {
        self.preferred_media_route = route;
    }

    /// Determine the best fallback route if the current route becomes
    /// unavailable (e.g., BT disconnect mid-session).
    ///
    /// Falls back to speaker for media, earpiece for calls.
    #[must_use]
    pub(crate) fn fallback_route(kind: SessionKind) -> AudioRoute {
        match kind {
            SessionKind::VoiceCall => AudioRoute::Earpiece,
            _ => AudioRoute::Speaker,
        }
    }

    /// Validate that a requested route is available and return it.
    ///
    /// Returns `Ok(route)` if the route is connected, allowing callers to
    /// use the validated route without re-stating it.
    /// Returns `Err(AudioError::RouteUnavailable)` when the route is not connected.
    pub(crate) fn validate_route(&self, route: AudioRoute) -> Result<AudioRoute, AudioError> {
        if self.is_output_available(route) {
            Ok(route)
        } else {
            Err(AudioError::RouteUnavailable)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn default_route_for_call_is_earpiece() {
        let mgr = RouteManager::new();
        assert_eq!(
            mgr.default_route_for(SessionKind::VoiceCall),
            AudioRoute::Earpiece,
            "voice call default route must be earpiece"
        );
    }

    #[test]
    fn default_route_for_music_is_speaker() {
        let mgr = RouteManager::new();
        assert_eq!(
            mgr.default_route_for(SessionKind::Music),
            AudioRoute::Speaker,
            "music default route must be speaker when no BT/USB connected"
        );
    }

    #[test]
    fn default_route_for_ringtone_is_speaker() {
        let mgr = RouteManager::new();
        assert_eq!(
            mgr.default_route_for(SessionKind::Ringtone),
            AudioRoute::Speaker,
            "ringtone default route must be speaker"
        );
    }

    #[test]
    fn default_route_for_alarm_is_speaker() {
        let mgr = RouteManager::new();
        assert_eq!(
            mgr.default_route_for(SessionKind::Alarm),
            AudioRoute::Speaker,
            "alarm default route must be speaker"
        );
    }

    #[test]
    fn default_route_for_notification_is_speaker() {
        let mgr = RouteManager::new();
        assert_eq!(
            mgr.default_route_for(SessionKind::Notification),
            AudioRoute::Speaker,
            "notification default route must be speaker"
        );
    }

    #[test]
    fn default_route_for_fm_is_speaker() {
        let mgr = RouteManager::new();
        assert_eq!(
            mgr.default_route_for(SessionKind::FmRadio),
            AudioRoute::Speaker,
            "FM radio default route must be speaker"
        );
    }

    #[test]
    fn toggle_speakerphone_swaps_route() {
        let mut mgr = RouteManager::new();

        // First toggle: earpiece -> speaker.
        let route = mgr.toggle_speakerphone();
        assert_eq!(
            route,
            AudioRoute::Speaker,
            "first toggle must switch to speaker"
        );
        assert!(
            mgr.is_speakerphone_active(),
            "speakerphone must be active after first toggle"
        );

        // Call route should now be speaker.
        assert_eq!(
            mgr.default_route_for(SessionKind::VoiceCall),
            AudioRoute::Speaker,
            "call route must be speaker when speakerphone active"
        );

        // Second toggle: speaker -> earpiece.
        let route = mgr.toggle_speakerphone();
        assert_eq!(
            route,
            AudioRoute::Earpiece,
            "second toggle must switch back to earpiece"
        );
        assert!(
            !mgr.is_speakerphone_active(),
            "speakerphone must be inactive after second toggle"
        );
    }

    #[test]
    fn bt_connected_updates_available() {
        let mut mgr = RouteManager::new();
        assert!(
            !mgr.is_output_available(AudioRoute::BluetoothA2dp),
            "BT must not be available initially"
        );

        mgr.notify_bt_connected();
        assert!(
            mgr.is_output_available(AudioRoute::BluetoothA2dp),
            "BT must be available after connect notification"
        );

        // Music should now prefer BT.
        assert_eq!(
            mgr.default_route_for(SessionKind::Music),
            AudioRoute::BluetoothA2dp,
            "music must prefer BT when connected"
        );
    }

    #[test]
    fn bt_disconnected_removes_from_available() {
        let mut mgr = RouteManager::new();
        mgr.notify_bt_connected();
        mgr.notify_bt_disconnected();
        assert!(
            !mgr.is_output_available(AudioRoute::BluetoothA2dp),
            "BT must not be available after disconnect"
        );

        // Music should fall back to speaker.
        assert_eq!(
            mgr.default_route_for(SessionKind::Music),
            AudioRoute::Speaker,
            "music must fall back to speaker after BT disconnect"
        );
    }

    #[test]
    fn headset_connected_updates_available() {
        let mut mgr = RouteManager::new();
        assert!(
            !mgr.is_output_available(AudioRoute::Headset),
            "headset must not be available initially"
        );

        mgr.notify_headset_connected();
        assert!(
            mgr.is_output_available(AudioRoute::Headset),
            "headset must be available after connect"
        );

        mgr.notify_headset_disconnected();
        assert!(
            !mgr.is_output_available(AudioRoute::Headset),
            "headset must not be available after disconnect"
        );
    }

    #[test]
    fn usb_dac_connected_prefers_for_music() {
        let mut mgr = RouteManager::new();
        mgr.notify_usb_dac_connected();

        assert_eq!(
            mgr.default_route_for(SessionKind::Music),
            AudioRoute::UsbDac,
            "music must prefer USB DAC when connected"
        );
    }

    #[test]
    fn usb_dac_preferred_over_bt() {
        let mut mgr = RouteManager::new();
        mgr.notify_bt_connected();
        mgr.notify_usb_dac_connected();

        // USB DAC takes priority over BT for music.
        assert_eq!(
            mgr.default_route_for(SessionKind::Music),
            AudioRoute::UsbDac,
            "USB DAC must be preferred over BT for music"
        );
    }

    #[test]
    fn duplicate_bt_connect_is_idempotent() {
        let mut mgr = RouteManager::new();
        mgr.notify_bt_connected();
        mgr.notify_bt_connected();

        // Should have exactly one BT entry.
        let bt_count = mgr
            .connected_outputs()
            .iter()
            .filter(|r| **r == AudioRoute::BluetoothA2dp)
            .count();
        assert_eq!(
            bt_count, 1,
            "duplicate connect must not add duplicate entry"
        );
    }

    #[test]
    fn validate_route_succeeds_for_builtin() {
        let mgr = RouteManager::new();
        assert!(
            mgr.validate_route(AudioRoute::Earpiece).is_ok(),
            "earpiece must always be available"
        );
        assert!(
            mgr.validate_route(AudioRoute::Speaker).is_ok(),
            "speaker must always be available"
        );
    }

    #[test]
    fn validate_route_fails_for_disconnected() {
        let mgr = RouteManager::new();
        assert_eq!(
            mgr.validate_route(AudioRoute::BluetoothA2dp),
            Err(AudioError::RouteUnavailable),
            "BT must be unavailable when not connected"
        );
    }

    #[test]
    fn fallback_route_for_call_is_earpiece() {
        assert_eq!(
            RouteManager::fallback_route(SessionKind::VoiceCall),
            AudioRoute::Earpiece,
            "call fallback must be earpiece"
        );
    }

    #[test]
    fn fallback_route_for_music_is_speaker() {
        assert_eq!(
            RouteManager::fallback_route(SessionKind::Music),
            AudioRoute::Speaker,
            "music fallback must be speaker"
        );
    }

    #[test]
    fn builtin_outputs_always_present() {
        let mgr = RouteManager::new();
        assert!(
            mgr.is_output_available(AudioRoute::Earpiece),
            "earpiece must always be connected"
        );
        assert!(
            mgr.is_output_available(AudioRoute::Speaker),
            "speaker must always be connected"
        );
    }

    #[test]
    fn set_preferred_call_route_changes_default() {
        let mut mgr = RouteManager::new();
        mgr.notify_bt_connected();
        mgr.set_preferred_call_route(AudioRoute::BluetoothA2dp);

        assert_eq!(
            mgr.default_route_for(SessionKind::VoiceCall),
            AudioRoute::BluetoothA2dp,
            "call route must follow preferred setting"
        );
    }

    #[test]
    fn audio_route_display() {
        assert_eq!(AudioRoute::Earpiece.to_string(), "earpiece",);
        assert_eq!(AudioRoute::Speaker.to_string(), "speaker",);
        assert_eq!(AudioRoute::BluetoothA2dp.to_string(), "bluetooth",);
        assert_eq!(AudioRoute::UsbDac.to_string(), "USB DAC",);
    }

    #[test]
    fn session_kind_display() {
        assert_eq!(SessionKind::VoiceCall.to_string(), "voice call",);
        assert_eq!(SessionKind::Music.to_string(), "music",);
    }

    #[test]
    fn route_unavailable_for_disconnected_bt() {
        let mgr = RouteManager::new();
        assert_eq!(
            mgr.validate_route(AudioRoute::BluetoothA2dp),
            Err(AudioError::RouteUnavailable),
            "must return RouteUnavailable for disconnected BT"
        );
        assert_eq!(
            mgr.validate_route(AudioRoute::UsbDac),
            Err(AudioError::RouteUnavailable),
            "must return RouteUnavailable for disconnected USB DAC"
        );
        assert_eq!(
            mgr.validate_route(AudioRoute::Headset),
            Err(AudioError::RouteUnavailable),
            "must return RouteUnavailable for disconnected headset"
        );
    }
}
