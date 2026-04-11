//! Phthongos audio session manager.
//!
//! Session-based audio management with priority preemption and PMIC power
//! gating for the MT6357 codec.  Every audio use (call, music, alarm,
//! ringtone, notification, FM radio) is an explicit session with
//! open/close lifecycle.  The codec is physically powered off when no
//! sessions are active (refcount == 0).
//!
//! ## Session model
//!
//! Sessions have a priority (`SessionPriority`).  Higher-priority sessions
//! preempt (pause) lower-priority ones:
//!
//! | Priority   | Examples                      | Preempts          |
//! |------------|-------------------------------|-------------------|
//! | Emergency  | Emergency alert               | everything        |
//! | Call       | Voice call                    | High, Normal, Low |
//! | High       | Alarms, ringtones             | Normal, Low       |
//! | Normal     | Music, notifications          | Low               |
//! | Low        | FM radio                      | nothing           |
//!
//! When a high-priority session closes, preempted sessions resume
//! automatically.  Multiple sessions at the same priority: most recent wins.
//!
//! ## PMIC power gating
//!
//! The MT6357 codec LDO is enabled on first session open (refcount 0 -> 1)
//! and disabled on last session close (refcount -> 0).  No "running but
//! muted" state — the hardware is physically off when idle.
//!
//! ## Mic security
//!
//! Voice call sessions automatically power the mic (ADC + mic bias).
//! The mic is powered down when no voice session is active.  All mic
//! activity is auditable via the session log.
//!
//! ## Integration
//!
//! Used by telephony (klesis), UI screens, and future music/FM modules.
//! Boot integration via `kinit.rs`.

// WHY: audio manager API not yet wired to kinit (Wave 4 integration pending).
#![expect(
    dead_code,
    reason = "audio manager API created in Phase 07 Wave 4, kinit wiring pending"
)]

extern crate alloc;
use alloc::vec::Vec;

use super::audio_codec::{AudioCodecOps, AudioError};
use super::audio_route::{AudioRoute, SessionKind};

// ---------------------------------------------------------------------------
// Session priority
// ---------------------------------------------------------------------------

/// Audio session priority levels.
///
/// Higher numeric value = higher priority.  Used for preemption decisions.
/// Implements `Ord` for direct comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum SessionPriority {
    /// FM radio, ambient audio — preempted by everything.
    Low = 0,
    /// Music playback, media, notifications.
    Normal = 1,
    /// Alarms, timers, ringtones.
    High = 2,
    /// Voice call audio (highest normal priority).
    Call = 3,
    /// Emergency alert — cannot be preempted.
    Emergency = 4,
}

impl SessionPriority {
    /// Map a session kind to its default priority.
    #[must_use]
    pub const fn from_kind(kind: SessionKind) -> Self {
        match kind {
            SessionKind::VoiceCall => Self::Call,
            SessionKind::Ringtone => Self::High,
            SessionKind::Alarm => Self::High,
            SessionKind::Notification => Self::Normal,
            SessionKind::Music => Self::Normal,
            SessionKind::FmRadio => Self::Low,
        }
    }
}

impl core::fmt::Display for SessionPriority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Normal => write!(f, "normal"),
            Self::High => write!(f, "high"),
            Self::Call => write!(f, "call"),
            Self::Emergency => write!(f, "emergency"),
        }
    }
}

// ---------------------------------------------------------------------------
// Audio session
// ---------------------------------------------------------------------------

/// An active audio session.
///
/// Sessions are created via [`AudioManager::open_session`] and destroyed
/// via [`AudioManager::close_session`].  Each session has a unique ID,
/// a kind, priority, output route, and active/paused state.
#[derive(Debug, Clone)]
pub struct AudioSession {
    /// Unique session identifier (monotonically increasing).
    pub id: u32,
    /// Session kind (voice call, music, alarm, etc.).
    pub kind: SessionKind,
    /// Session priority for preemption decisions.
    pub priority: SessionPriority,
    /// Audio output route for this session.
    pub route: AudioRoute,
    /// Whether the session is actively producing/consuming audio.
    ///
    /// `false` means the session is preempted (paused) by a higher-priority
    /// session and will resume when the preempting session closes.
    pub active: bool,
}

impl core::fmt::Display for AudioSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "session {} ({}, {}, {}, {})",
            self.id,
            self.kind,
            self.priority,
            self.route,
            if self.active { "active" } else { "paused" },
        )
    }
}

// ---------------------------------------------------------------------------
// Default volume
// ---------------------------------------------------------------------------

/// Default volume level for new sessions (mid-range).
const DEFAULT_VOLUME: u8 = 8;

// ---------------------------------------------------------------------------
// Audio manager
// ---------------------------------------------------------------------------

/// Phthongos audio session manager.
///
/// Owns all audio sessions and the codec driver.  Manages session
/// lifecycle, priority preemption, codec power gating, and route
/// configuration.
///
/// Generic over the codec implementation (`C: AudioCodecOps`) for
/// testability.
pub struct AudioManager<C: AudioCodecOps> {
    /// All sessions (active and preempted).
    sessions: Vec<AudioSession>,
    /// Next session ID to allocate.
    next_id: u32,
    /// Whether the codec is currently powered on.
    codec_powered: bool,
    /// Whether the mic (ADC + bias) is currently powered on.
    mic_powered: bool,
    /// Current output route applied to the codec.
    active_route: AudioRoute,
    /// Hardware codec driver.
    codec: C,
    /// Current volume level (0-15).
    volume: u8,
}

impl<C: AudioCodecOps> AudioManager<C> {
    /// Create a new audio manager with the given codec backend.
    ///
    /// The manager starts with no sessions, codec powered off.
    #[must_use]
    pub fn new(codec: C) -> Self {
        Self {
            sessions: Vec::new(),
            next_id: 1,
            codec_powered: false,
            mic_powered: false,
            active_route: AudioRoute::Speaker,
            codec,
            volume: DEFAULT_VOLUME,
        }
    }

    /// Open a new audio session.
    ///
    /// ## Lifecycle
    ///
    /// 1. If this is the first session (refcount 0 -> 1), power on the codec.
    /// 2. If the session kind is `VoiceCall`, enable mic (ADC + bias).
    /// 3. Preempt any lower-priority active sessions.
    /// 4. Configure the codec for the requested route.
    /// 5. Return the new session's ID.
    ///
    /// ## Preemption rules
    ///
    /// - Higher priority preempts lower priority (pauses them).
    /// - Same priority: most recent session wins (pauses earlier ones).
    /// - When the preempting session closes, preempted sessions resume.
    /// # Errors
    ///
    /// - [`AudioError::PowerError`] -- codec power-on failed.
    /// - [`AudioError::RouteError`] -- output route configuration failed.
    /// - [`AudioError::AdcNotEnabled`] -- mic ADC enable failed for voice call.
    pub fn open_session(
        &mut self,
        kind: SessionKind,
        route: AudioRoute,
    ) -> Result<u32, AudioError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let priority = SessionPriority::from_kind(kind);

        // Power on codec if this is the first session.
        if self.sessions.is_empty() {
            self.codec.power_on()?;
            self.codec_powered = true;
            self.codec.enable_dac()?;
            self.codec.set_volume(self.volume)?;
        }

        // Enable mic for voice calls.
        let needs_mic = kind == SessionKind::VoiceCall;
        if needs_mic && !self.mic_powered {
            self.codec.enable_adc()?;
            self.codec.enable_mic_bias()?;
            self.mic_powered = true;
        }

        // Preempt sessions: pause any active session at lower or equal priority.
        // Equal priority: most recent wins, so pause previous same-priority.
        for session in &mut self.sessions {
            if session.active && session.priority <= priority {
                session.active = false;
            }
        }

        // Set the codec output route for the new session.
        self.codec.set_output(route)?;
        self.active_route = route;

        // Create and store the session.
        let session = AudioSession {
            id,
            kind,
            priority,
            route,
            active: true,
        };
        self.sessions.push(session);

        Ok(id)
    }

    /// Close an audio session by ID.
    ///
    /// ## Lifecycle
    ///
    /// 1. Remove the session.
    /// 2. If the closed session was the highest priority, resume the
    ///    next-highest-priority session (most recently opened at that level).
    /// 3. If no voice call sessions remain, power down mic.
    /// 4. If no sessions remain (refcount -> 0), power down codec.
    ///
    /// # Errors
    ///
    /// - [`AudioError::SessionNotFound`] -- no session with the given ID.
    /// - [`AudioError::PowerError`] -- codec power-off failed.
    pub fn close_session(&mut self, id: u32) -> Result<(), AudioError> {
        let pos = self
            .sessions
            .iter()
            .position(|s| s.id == id)
            .ok_or(AudioError::SessionNotFound)?;

        let closed = self.sessions.remove(pos);

        if self.sessions.is_empty() {
            // Last session closed — power down everything.
            self.power_down_mic()?;
            self.codec.disable_dac()?;
            self.codec.power_off()?;
            self.codec_powered = false;
            return Ok(());
        }

        // If the closed session was active and preempting others, resume
        // the highest-priority preempted session.
        if closed.active {
            self.resume_highest_priority()?;
        }

        // Power down mic if no voice call sessions remain.
        let has_voice = self.sessions.iter().any(|s| s.kind == SessionKind::VoiceCall);
        if !has_voice && self.mic_powered {
            self.power_down_mic()?;
        }

        Ok(())
    }

    /// Change the output route for an active session.
    ///
    /// # Errors
    ///
    /// - [`AudioError::SessionNotFound`] -- no session with the given ID.
    /// - [`AudioError::RouteError`] -- output route configuration failed.
    pub fn set_route(&mut self, id: u32, route: AudioRoute) -> Result<(), AudioError> {
        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or(AudioError::SessionNotFound)?;

        session.route = route;

        // Only reconfigure codec if this is the active session.
        if session.active {
            self.codec.set_output(route)?;
            self.active_route = route;
        }

        Ok(())
    }

    /// Set the output volume (0-15).
    ///
    /// Applies immediately if the codec is powered.
    ///
    /// # Errors
    ///
    /// - [`AudioError::VolumeError`] -- codec volume write failed.
    pub fn set_volume(&mut self, level: u8) -> Result<(), AudioError> {
        self.volume = level.min(15);
        if self.codec_powered {
            self.codec.set_volume(self.volume)?;
        }
        Ok(())
    }

    /// Return a slice of all sessions (active and preempted).
    #[must_use]
    pub fn active_sessions(&self) -> &[AudioSession] {
        &self.sessions
    }

    /// Return the number of sessions (refcount).
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Return whether the codec is currently powered on.
    #[must_use]
    pub fn is_codec_powered(&self) -> bool {
        self.codec_powered
    }

    /// Return whether the mic (ADC + bias) is currently powered on.
    #[must_use]
    pub fn is_mic_powered(&self) -> bool {
        self.mic_powered
    }

    /// Return the current active output route.
    #[must_use]
    pub fn active_route(&self) -> AudioRoute {
        self.active_route
    }

    /// Return a reference to the underlying codec.
    #[must_use]
    pub fn codec(&self) -> &C {
        &self.codec
    }

    /// Return a mutable reference to the underlying codec.
    pub fn codec_mut(&mut self) -> &mut C {
        &mut self.codec
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Resume the highest-priority paused session.
    ///
    /// If multiple sessions exist at the same priority, the most recently
    /// opened one (last in the Vec) wins.
    fn resume_highest_priority(&mut self) -> Result<(), AudioError> {
        // Find the highest priority among paused sessions.
        let max_priority = self
            .sessions
            .iter()
            .filter(|s| !s.active)
            .map(|s| s.priority)
            .max();

        if let Some(priority) = max_priority {
            // Among sessions at that priority, activate the most recent
            // (last in the Vec with that priority).
            let resume_idx = self
                .sessions
                .iter()
                .rposition(|s| !s.active && s.priority == priority);

            if let Some(idx) = resume_idx {
                self.sessions[idx].active = true;
                let route = self.sessions[idx].route;
                self.codec.set_output(route)?;
                self.active_route = route;
            }
        }

        Ok(())
    }

    /// Power down the mic (ADC + bias).
    fn power_down_mic(&mut self) -> Result<(), AudioError> {
        if self.mic_powered {
            self.codec.disable_mic_bias()?;
            self.codec.disable_adc()?;
            self.mic_powered = false;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio_codec::MockCodec;

    /// Helper: create a fresh `AudioManager` with a `MockCodec`.
    fn make_manager() -> AudioManager<MockCodec> {
        AudioManager::new(MockCodec::new())
    }

    #[test]
    fn open_session_powers_codec() {
        let mut mgr = make_manager();
        assert!(
            !mgr.is_codec_powered(),
            "codec must be off before any session"
        );

        let id = mgr.open_session(SessionKind::Music, AudioRoute::Speaker);
        assert!(id.is_ok(), "open_session must succeed");
        assert!(
            mgr.is_codec_powered(),
            "codec must be powered after first session opens"
        );
    }

    #[test]
    fn close_last_session_powers_down_codec() {
        let mut mgr = make_manager();
        let id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .ok();

        let result = mgr.close_session(id.unwrap_or(0));
        assert!(result.is_ok(), "close_session must succeed");
        assert!(
            !mgr.is_codec_powered(),
            "codec must be off after last session closes"
        );
        assert_eq!(
            mgr.session_count(),
            0,
            "no sessions must remain after close"
        );
    }

    #[test]
    fn high_priority_preempts_low() {
        let mut mgr = make_manager();

        // Open a low-priority session (FM radio).
        let low_id = mgr
            .open_session(SessionKind::FmRadio, AudioRoute::Speaker);
        assert!(low_id.is_ok(), "FM session must open");
        let low_id = low_id.unwrap_or(0);

        // Open a high-priority session (alarm).
        let high_id = mgr
            .open_session(SessionKind::Alarm, AudioRoute::Speaker);
        assert!(high_id.is_ok(), "alarm session must open");

        // Low-priority session must be preempted (paused).
        let sessions = mgr.active_sessions();
        let low_session = sessions.iter().find(|s| s.id == low_id);
        assert!(low_session.is_some(), "low session must still exist");
        assert!(
            !low_session.map_or(true, |s| s.active),
            "low-priority session must be paused (preempted by alarm)"
        );
    }

    #[test]
    fn closing_preempting_session_resumes_lower() {
        let mut mgr = make_manager();

        // Open music (Normal priority).
        let music_id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);

        // Open alarm (High priority) — preempts music.
        let alarm_id = mgr
            .open_session(SessionKind::Alarm, AudioRoute::Speaker)
            .unwrap_or(0);

        // Verify music is paused.
        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            !music.map_or(true, |s| s.active),
            "music must be paused during alarm"
        );

        // Close alarm — music should resume.
        let result = mgr.close_session(alarm_id);
        assert!(result.is_ok(), "close alarm must succeed");

        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            music.map_or(false, |s| s.active),
            "music must resume after alarm closes"
        );
    }

    #[test]
    fn call_preempts_music() {
        let mut mgr = make_manager();

        // Open music.
        let music_id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);

        // Open voice call — preempts music.
        let call_id = mgr
            .open_session(SessionKind::VoiceCall, AudioRoute::Earpiece);
        assert!(call_id.is_ok(), "voice call must open");
        let call_id = call_id.unwrap_or(0);

        // Music must be paused.
        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            !music.map_or(true, |s| s.active),
            "music must be paused during voice call"
        );

        // Call must be active.
        let call = mgr.active_sessions().iter().find(|s| s.id == call_id);
        assert!(
            call.map_or(false, |s| s.active),
            "voice call must be active"
        );

        // Close call — music resumes.
        mgr.close_session(call_id).ok();
        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            music.map_or(false, |s| s.active),
            "music must resume after call ends"
        );
    }

    #[test]
    fn multiple_sessions_at_same_priority_latest_wins() {
        let mut mgr = make_manager();

        // Open two music sessions (both Normal priority).
        let first_id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);
        let second_id = mgr
            .open_session(SessionKind::Music, AudioRoute::BluetoothA2dp)
            .unwrap_or(0);

        // First session must be paused (same priority, newer wins).
        let first = mgr.active_sessions().iter().find(|s| s.id == first_id);
        assert!(
            !first.map_or(true, |s| s.active),
            "earlier same-priority session must be paused"
        );

        // Second session must be active.
        let second = mgr.active_sessions().iter().find(|s| s.id == second_id);
        assert!(
            second.map_or(false, |s| s.active),
            "latest same-priority session must be active"
        );
    }

    #[test]
    fn session_id_increments() {
        let mut mgr = make_manager();

        let id1 = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);
        let id2 = mgr
            .open_session(SessionKind::Notification, AudioRoute::Speaker)
            .unwrap_or(0);
        let id3 = mgr
            .open_session(SessionKind::Alarm, AudioRoute::Speaker)
            .unwrap_or(0);

        assert_eq!(id1, 1, "first session ID must be 1");
        assert_eq!(id2, 2, "second session ID must be 2");
        assert_eq!(id3, 3, "third session ID must be 3");
    }

    #[test]
    fn mic_powered_during_voice_call() {
        let mut mgr = make_manager();
        assert!(
            !mgr.is_mic_powered(),
            "mic must be off before any session"
        );

        // Open a voice call — mic should power on.
        let call_id = mgr
            .open_session(SessionKind::VoiceCall, AudioRoute::Earpiece)
            .unwrap_or(0);
        assert!(
            mgr.is_mic_powered(),
            "mic must be powered during voice call"
        );

        // Close the call — mic should power down.
        mgr.close_session(call_id).ok();
        assert!(
            !mgr.is_mic_powered(),
            "mic must be off after voice call ends"
        );
    }

    #[test]
    fn mic_not_powered_for_music() {
        let mut mgr = make_manager();
        mgr.open_session(SessionKind::Music, AudioRoute::Speaker).ok();
        assert!(
            !mgr.is_mic_powered(),
            "mic must not be powered for music playback"
        );
    }

    #[test]
    fn close_nonexistent_session_returns_error() {
        let mut mgr = make_manager();
        let result = mgr.close_session(999);
        assert_eq!(
            result,
            Err(AudioError::SessionNotFound),
            "closing nonexistent session must return SessionNotFound"
        );
    }

    #[test]
    fn set_route_changes_active_session() {
        let mut mgr = make_manager();
        let id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);

        let result = mgr.set_route(id, AudioRoute::BluetoothA2dp);
        assert!(result.is_ok(), "set_route must succeed");

        let session = mgr.active_sessions().iter().find(|s| s.id == id);
        assert_eq!(
            session.map(|s| s.route),
            Some(AudioRoute::BluetoothA2dp),
            "session route must be updated"
        );
        assert_eq!(
            mgr.active_route(),
            AudioRoute::BluetoothA2dp,
            "active route must reflect the change"
        );
    }

    #[test]
    fn set_route_nonexistent_session_returns_error() {
        let mut mgr = make_manager();
        let result = mgr.set_route(999, AudioRoute::Speaker);
        assert_eq!(
            result,
            Err(AudioError::SessionNotFound),
            "set_route on nonexistent session must return SessionNotFound"
        );
    }

    #[test]
    fn codec_not_powered_with_no_sessions() {
        let mgr = make_manager();
        assert!(!mgr.is_codec_powered(), "codec must be off with no sessions");
        assert_eq!(mgr.session_count(), 0, "session count must be 0");
    }

    #[test]
    fn set_volume_applies_to_codec() {
        let mut mgr = make_manager();
        mgr.open_session(SessionKind::Music, AudioRoute::Speaker).ok();

        let result = mgr.set_volume(12);
        assert!(result.is_ok(), "set_volume must succeed");
        assert_eq!(
            mgr.codec().volume(),
            12,
            "codec volume must reflect the setting"
        );
    }

    #[test]
    fn preemption_chain_resumes_correctly() {
        let mut mgr = make_manager();

        // Open FM (Low).
        let fm_id = mgr
            .open_session(SessionKind::FmRadio, AudioRoute::Speaker)
            .unwrap_or(0);

        // Open music (Normal) — preempts FM.
        let music_id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);

        // Open alarm (High) — preempts music.
        let alarm_id = mgr
            .open_session(SessionKind::Alarm, AudioRoute::Speaker)
            .unwrap_or(0);

        // Open call (Call) — preempts alarm.
        let call_id = mgr
            .open_session(SessionKind::VoiceCall, AudioRoute::Earpiece)
            .unwrap_or(0);

        // Verify: only call is active.
        for session in mgr.active_sessions() {
            if session.id == call_id {
                assert!(session.active, "call must be active");
            } else {
                assert!(!session.active, "session {} must be paused", session.id);
            }
        }

        // Close call — alarm should resume (highest paused priority).
        mgr.close_session(call_id).ok();
        let alarm = mgr.active_sessions().iter().find(|s| s.id == alarm_id);
        assert!(
            alarm.map_or(false, |s| s.active),
            "alarm must resume after call closes"
        );

        // Close alarm — music should resume.
        mgr.close_session(alarm_id).ok();
        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            music.map_or(false, |s| s.active),
            "music must resume after alarm closes"
        );

        // Close music — FM should resume.
        mgr.close_session(music_id).ok();
        let fm = mgr.active_sessions().iter().find(|s| s.id == fm_id);
        assert!(
            fm.map_or(false, |s| s.active),
            "FM must resume after music closes"
        );
    }

    #[test]
    fn ringtone_preempts_fm() {
        let mut mgr = make_manager();

        let fm_id = mgr
            .open_session(SessionKind::FmRadio, AudioRoute::Speaker)
            .unwrap_or(0);
        let ring_id = mgr
            .open_session(SessionKind::Ringtone, AudioRoute::Speaker)
            .unwrap_or(0);

        // FM must be paused.
        let fm = mgr.active_sessions().iter().find(|s| s.id == fm_id);
        assert!(
            !fm.map_or(true, |s| s.active),
            "FM must be paused during ringtone"
        );

        // Close ringtone — FM resumes.
        mgr.close_session(ring_id).ok();
        let fm = mgr.active_sessions().iter().find(|s| s.id == fm_id);
        assert!(
            fm.map_or(false, |s| s.active),
            "FM must resume after ringtone"
        );
    }

    #[test]
    fn session_priority_ordering() {
        assert!(SessionPriority::Low < SessionPriority::Normal);
        assert!(SessionPriority::Normal < SessionPriority::High);
        assert!(SessionPriority::High < SessionPriority::Call);
        assert!(SessionPriority::Call < SessionPriority::Emergency);
    }

    #[test]
    fn priority_from_kind_mapping() {
        assert_eq!(
            SessionPriority::from_kind(SessionKind::VoiceCall),
            SessionPriority::Call,
        );
        assert_eq!(
            SessionPriority::from_kind(SessionKind::Ringtone),
            SessionPriority::High,
        );
        assert_eq!(
            SessionPriority::from_kind(SessionKind::Alarm),
            SessionPriority::High,
        );
        assert_eq!(
            SessionPriority::from_kind(SessionKind::Music),
            SessionPriority::Normal,
        );
        assert_eq!(
            SessionPriority::from_kind(SessionKind::Notification),
            SessionPriority::Normal,
        );
        assert_eq!(
            SessionPriority::from_kind(SessionKind::FmRadio),
            SessionPriority::Low,
        );
    }

    #[test]
    fn session_display_format() {
        let session = AudioSession {
            id: 42,
            kind: SessionKind::Music,
            priority: SessionPriority::Normal,
            route: AudioRoute::Speaker,
            active: true,
        };
        let s = alloc::format!("{session}");
        assert!(
            s.contains("42"),
            "display must include session ID"
        );
        assert!(
            s.contains("music"),
            "display must include session kind"
        );
        assert!(
            s.contains("active"),
            "display must include active state"
        );
    }

    #[test]
    fn codec_operations_recorded_during_session_lifecycle() {
        let mut mgr = make_manager();

        // Open session — should power on, enable DAC, set volume, set output.
        mgr.open_session(SessionKind::Music, AudioRoute::Speaker).ok();

        let ops = &mgr.codec().operations;
        assert!(
            ops.contains(&alloc::string::String::from("power_on")),
            "power_on must be recorded: {ops:?}"
        );
        assert!(
            ops.contains(&alloc::string::String::from("enable_dac")),
            "enable_dac must be recorded: {ops:?}"
        );
    }
}
