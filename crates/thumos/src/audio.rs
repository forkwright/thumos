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
// cfg_attr(not(test), ...): the module's own tests now exercise its full
// surface, so nothing is dead in the test build -- expecting dead_code there
// makes the expectation unfulfilled. Production reachability is unchanged;
// the expectation is scoped to the build where it is still real.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "audio manager API exists; kinit wiring pending (#753; tier in docs/capability-inventory.toml)"
    )
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
    pub(crate) const fn from_kind(kind: SessionKind) -> Self {
        match kind {
            SessionKind::VoiceCall => Self::Call,
            SessionKind::Ringtone | SessionKind::Alarm => Self::High,
            SessionKind::Notification | SessionKind::Music => Self::Normal,
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
pub(crate) struct AudioManager<C: AudioCodecOps> {
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
    pub(crate) fn new(codec: C) -> Self {
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
    /// 1. If this is the first session (refcount 0 -> 1), power on the
    ///    codec. Any hardware failure from this step onward rolls back
    ///    what this call powered on and returns before any session state
    ///    is mutated (#390) — `open_session` has a single commit point.
    /// 2. If the session kind is `VoiceCall`, enable mic (ADC + bias);
    ///    on failure, roll back the ADC if it was already enabled.
    /// 3. Configure the codec for the requested route, unless a strictly
    ///    higher-priority session is already active (in which case the
    ///    new session is inserted paused instead, #386). This is the
    ///    commit point: no previously-active session is paused before
    ///    this succeeds.
    /// 4. Preempt any active session at lower-or-equal priority.
    /// 5. Push the new session and return its ID.
    ///
    /// ## Preemption rules
    ///
    /// - Higher priority preempts lower priority (pauses them).
    /// - Same priority: most recent session wins (pauses earlier ones).
    /// - A session opened while a strictly higher-priority session is
    ///   active is itself inserted paused, not active: it does not touch
    ///   the codec route and resumes automatically when the higher-priority
    ///   session closes.
    /// - When the preempting session closes, preempted sessions resume.
    /// # Errors
    ///
    /// - [`AudioError::PowerError`] -- codec power-on failed.
    /// - [`AudioError::RouteError`] -- output route configuration failed.
    /// - [`AudioError::AdcNotEnabled`] -- mic ADC enable failed for voice call.
    pub(crate) fn open_session(
        &mut self,
        kind: SessionKind,
        route: AudioRoute,
    ) -> Result<u32, AudioError> {
        let priority = SessionPriority::from_kind(kind);
        let first_session = self.sessions.is_empty();

        // Power on codec if this is the first session. A failure at any
        // step here must roll the codec back to powered-off (#390) — the
        // only prior commit was self.codec_powered, which we also revert.
        if first_session {
            self.codec.power_on()?;
            self.codec_powered = true;

            if let Err(err) = self.codec.enable_dac() {
                self.codec.power_off().ok();
                self.codec_powered = false;
                return Err(err);
            }
            if let Err(err) = self.codec.set_volume(self.volume) {
                self.codec.power_off().ok();
                self.codec_powered = false;
                return Err(err);
            }
        }

        // Enable mic for voice calls. Roll back the ADC if mic bias fails
        // to enable, so codec.adc_enabled and mgr.is_mic_powered() never
        // disagree (#390) — an ADC left hot with no mic-powered session
        // recorded is an unauditable microphone.
        let needs_mic = kind == SessionKind::VoiceCall;
        if needs_mic && !self.mic_powered {
            if let Err(err) = self.codec.enable_adc() {
                if first_session {
                    self.codec.power_off().ok();
                    self.codec_powered = false;
                }
                return Err(err);
            }
            if let Err(err) = self.codec.enable_mic_bias() {
                self.codec.disable_adc().ok();
                if first_session {
                    self.codec.power_off().ok();
                    self.codec_powered = false;
                }
                return Err(err);
            }
            self.mic_powered = true;
        }

        // WHY: a strictly-higher-priority active session is unaffected by
        // preemption (only <= priority sessions get paused below), so it
        // is safe to compute this before the preemption loop runs — the
        // set of higher-priority actives is the same before and after.
        // The new session must not become active, and must not touch the
        // codec route, or it silently displaces the higher-priority
        // session's audio (#386).
        let blocked_by_higher_priority = self
            .sessions
            .iter()
            .any(|s| s.active && s.priority > priority);

        // Commit point: set the codec output route for the new session,
        // unless a strictly higher-priority session is already active.
        // No session state is mutated before this succeeds (#390) — a
        // set_output failure must not permanently strand previously-active
        // sessions paused with no path to resume them.
        if !blocked_by_higher_priority {
            self.codec.set_output(route)?;
            self.active_route = route;
        }

        // Every hardware operation has succeeded — pause preempted
        // sessions and push the new one. Equal priority: most recent
        // wins, so pause previous same-priority.
        for session in &mut self.sessions {
            if session.active && session.priority <= priority {
                session.active = false;
            }
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        // Starts paused if a higher-priority session is active; it
        // resumes automatically via resume_highest_priority() when that
        // session closes.
        let session = AudioSession {
            id,
            kind,
            priority,
            route,
            active: !blocked_by_higher_priority,
        };
        self.sessions.push(session);

        self.debug_check_single_active_invariant();
        Ok(id)
    }

    /// Close an audio session by ID.
    ///
    /// ## Lifecycle
    ///
    /// 1. If this is the last session (refcount -> 0), power down mic,
    ///    disable the DAC, and power off the codec BEFORE removing the
    ///    session from the list -- a hardware failure here leaves the
    ///    session tracked so `codec_powered`/`mic_powered` still match
    ///    reality and the close can be retried.
    /// 2. Otherwise, remove the session; if it was the highest priority,
    ///    resume the next-highest-priority session (most recently opened
    ///    at that level).
    /// 3. If no voice call sessions remain, power down mic.
    ///
    /// # Errors
    ///
    /// - [`AudioError::SessionNotFound`] -- no session with the given ID.
    /// - [`AudioError::PowerError`] -- codec power-off failed.
    pub(crate) fn close_session(&mut self, id: u32) -> Result<(), AudioError> {
        let pos = self
            .sessions
            .iter()
            .position(|s| s.id == id)
            .ok_or(AudioError::SessionNotFound)?;

        if self.sessions.len() == 1 {
            // WHY: power down everything BEFORE removing the session
            // from the list (mirrors the #390 commit-point pattern) --
            // if any hardware teardown call fails, the session must
            // stay tracked so codec_powered/mic_powered keep describing
            // reality and a retry is possible. Removing first would
            // strand a still-powered codec with no session left to
            // close it.
            self.power_down_mic()?;
            self.codec.disable_dac()?;
            self.codec.power_off()?;
            self.codec_powered = false;
            self.sessions.remove(pos);
            self.debug_check_single_active_invariant();
            return Ok(());
        }

        let closed = self.sessions.remove(pos);

        // If the closed session was active and preempting others, resume
        // the highest-priority preempted session.
        if closed.active {
            self.resume_highest_priority()?;
        }

        // Power down mic if no voice call sessions remain.
        let has_voice = self
            .sessions
            .iter()
            .any(|s| s.kind == SessionKind::VoiceCall);
        if !has_voice && self.mic_powered {
            self.power_down_mic()?;
        }

        self.debug_check_single_active_invariant();
        Ok(())
    }

    /// Change the output route for an active session.
    ///
    /// # Errors
    ///
    /// - [`AudioError::SessionNotFound`] -- no session with the given ID.
    /// - [`AudioError::RouteError`] -- output route configuration failed.
    pub(crate) fn set_route(&mut self, id: u32, route: AudioRoute) -> Result<(), AudioError> {
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
    pub(crate) fn set_volume(&mut self, level: u8) -> Result<(), AudioError> {
        // WHY: write the hardware first, then update the cached field --
        // previously self.volume was updated unconditionally before the
        // hardware write, so a failed write left the cached value
        // diverged from the codec's actual (unchanged) volume.
        let clamped = level.min(15);
        if self.codec_powered {
            self.codec.set_volume(clamped)?;
        }
        self.volume = clamped;
        Ok(())
    }

    /// Return a slice of all sessions (active and preempted).
    #[must_use]
    pub(crate) fn active_sessions(&self) -> &[AudioSession] {
        &self.sessions
    }

    /// Return the number of sessions (refcount).
    #[must_use]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Return whether the codec is currently powered on.
    #[must_use]
    pub(crate) fn is_codec_powered(&self) -> bool {
        self.codec_powered
    }

    /// Return whether the mic (ADC + bias) is currently powered on.
    #[must_use]
    pub(crate) fn is_mic_powered(&self) -> bool {
        self.mic_powered
    }

    /// Return the current active output route.
    #[must_use]
    pub(crate) fn active_route(&self) -> AudioRoute {
        self.active_route
    }

    /// Return a reference to the underlying codec.
    #[must_use]
    pub(crate) fn codec(&self) -> &C {
        &self.codec
    }

    /// Return a mutable reference to the underlying codec.
    ///
    /// WHY test-only: production code must reach the codec ONLY through
    /// the auditable session lifecycle (`open_session/close_session`/
    /// `set_route/set_volume`) -- this raw accessor bypasses that entirely,
    /// letting a caller flip `enable_mic_bias()/enable_adc()` with no
    /// `AudioSession` ever recorded, defeating the "all mic activity is
    /// auditable via the session log" invariant documented at the top of
    /// this module. Grepped: every call site in the tree is this file's
    /// own `#[cfg(test)] mod tests` (fault injection on `MockCodec`); no
    /// production caller exists (#397).
    #[cfg(test)]
    pub(crate) fn codec_mut(&mut self) -> &mut C {
        &mut self.codec
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Debug invariant: at most one session may be active at a time.
    ///
    /// Compiled out in release builds (`debug_assert!`). Invoked at the end
    /// of [`Self::open_session`] and [`Self::close_session`] — the two
    /// methods that mutate session activation state — to catch a
    /// preemption-logic regression like #386 immediately instead of via a
    /// silently-corrupted `active_route`.
    fn debug_check_single_active_invariant(&self) {
        debug_assert!(
            self.sessions.iter().filter(|s| s.active).count() <= 1,
            "AudioManager invariant violated: more than one active session"
        );
    }

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
                // WHY: confirm the hardware route BEFORE marking the
                // session active -- otherwise a set_output failure left
                // the session flagged active while the codec never
                // actually switched to its route.
                let route = self.sessions[idx].route;
                self.codec.set_output(route)?;
                self.sessions[idx].active = true;
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

impl<C: AudioCodecOps> Drop for AudioManager<C> {
    /// Backstop against any path that leaves the codec physically powered
    /// with no session recorded (#390) — a stranded LDO drains power
    /// indefinitely on a power-constrained device. Best-effort: a failure
    /// here is not actionable during drop.
    fn drop(&mut self) {
        if self.codec_powered {
            self.codec.power_off().ok();
        }
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
    fn set_volume_leaves_field_unchanged_when_hardware_write_fails() {
        let mut mgr = make_manager();
        mgr.open_session(SessionKind::Music, AudioRoute::Speaker)
            .ok();
        let original = mgr.volume;

        // Desync the mock codec's internal powered flag so its
        // set_volume call fails while the manager still believes the
        // codec is on (mirrors a hardware write glitch).
        mgr.codec_mut().powered = false;

        let result = mgr.set_volume(3);
        assert!(
            result.is_err(),
            "set_volume must propagate the hardware failure"
        );
        assert_eq!(
            mgr.volume, original,
            "the cached volume field must not change when the hardware \
             write fails -- it would otherwise diverge from the actual \
             (unwritten) hardware volume"
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
    fn close_last_session_keeps_session_tracked_when_disable_dac_fails() {
        let mut mgr = make_manager();
        let id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);

        mgr.codec_mut().fail_disable_dac = Some(AudioError::HardwareError);

        let result = mgr.close_session(id);
        assert!(
            result.is_err(),
            "close_session must propagate the disable_dac failure"
        );
        assert_eq!(
            mgr.session_count(),
            1,
            "the session must stay tracked when hardware teardown fails -- \
             removing it first would strand a still-powered codec with no \
             session left to retry the close"
        );
        assert!(
            mgr.is_codec_powered(),
            "codec_powered must still be true -- it matches reality, the \
             codec never actually powered off"
        );

        // Recovery: clear the injected failure and retry the close.
        mgr.codec_mut().fail_disable_dac = None;
        let result = mgr.close_session(id);
        assert!(
            result.is_ok(),
            "close_session must succeed once the hardware call stops failing"
        );
        assert_eq!(mgr.session_count(), 0);
        assert!(!mgr.is_codec_powered());
    }

    #[test]
    fn close_last_session_keeps_session_tracked_when_power_off_fails() {
        let mut mgr = make_manager();
        let id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);

        mgr.codec_mut().fail_power_off = Some(AudioError::HardwareError);

        let result = mgr.close_session(id);
        assert!(
            result.is_err(),
            "close_session must propagate the power_off failure"
        );
        assert_eq!(
            mgr.session_count(),
            1,
            "the session must stay tracked when power_off fails"
        );
        assert!(mgr.is_codec_powered());

        mgr.codec_mut().fail_power_off = None;
        let result = mgr.close_session(id);
        assert!(result.is_ok());
        assert_eq!(mgr.session_count(), 0);
        assert!(!mgr.is_codec_powered());
    }

    #[test]
    fn high_priority_preempts_low() {
        let mut mgr = make_manager();

        // Open a low-priority session (FM radio).
        let low_id = mgr.open_session(SessionKind::FmRadio, AudioRoute::Speaker);
        assert!(low_id.is_ok(), "FM session must open");
        let low_id = low_id.unwrap_or(0);

        // Open a high-priority session (alarm).
        let high_id = mgr.open_session(SessionKind::Alarm, AudioRoute::Speaker);
        assert!(high_id.is_ok(), "alarm session must open");

        // Low-priority session must be preempted (paused).
        let sessions = mgr.active_sessions();
        let low_session = sessions.iter().find(|s| s.id == low_id);
        assert!(low_session.is_some(), "low session must still exist");
        assert!(
            !low_session.is_none_or(|s| s.active),
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
            !music.is_none_or(|s| s.active),
            "music must be paused during alarm"
        );

        // Close alarm — music should resume.
        let result = mgr.close_session(alarm_id);
        assert!(result.is_ok(), "close alarm must succeed");

        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            music.is_some_and(|s| s.active),
            "music must resume after alarm closes"
        );
    }

    #[test]
    fn resume_highest_priority_does_not_mark_active_when_route_fails() {
        let mut mgr = make_manager();

        let music_id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);
        let alarm_id = mgr
            .open_session(SessionKind::Alarm, AudioRoute::Speaker)
            .unwrap_or(0);

        // Make the resume's set_output fail.
        mgr.codec_mut().fail_set_output = Some(AudioError::HardwareError);

        let result = mgr.close_session(alarm_id);
        assert!(
            result.is_err(),
            "close_session must propagate the resume failure"
        );

        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            !music.is_none_or(|s| s.active),
            "music must NOT be marked active when the resume's set_output failed"
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
        let call_id = mgr.open_session(SessionKind::VoiceCall, AudioRoute::Earpiece);
        assert!(call_id.is_ok(), "voice call must open");
        let call_id = call_id.unwrap_or(0);

        // Music must be paused.
        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            !music.is_none_or(|s| s.active),
            "music must be paused during voice call"
        );

        // Call must be active.
        let call = mgr.active_sessions().iter().find(|s| s.id == call_id);
        assert!(call.is_some_and(|s| s.active), "voice call must be active");

        // Close call — music resumes.
        mgr.close_session(call_id).ok();
        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            music.is_some_and(|s| s.active),
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
            !first.is_none_or(|s| s.active),
            "earlier same-priority session must be paused"
        );

        // Second session must be active.
        let second = mgr.active_sessions().iter().find(|s| s.id == second_id);
        assert!(
            second.is_some_and(|s| s.active),
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
        assert!(!mgr.is_mic_powered(), "mic must be off before any session");

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
        mgr.open_session(SessionKind::Music, AudioRoute::Speaker)
            .ok();
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
        assert!(
            !mgr.is_codec_powered(),
            "codec must be off with no sessions"
        );
        assert_eq!(mgr.session_count(), 0, "session count must be 0");
    }

    #[test]
    fn set_volume_applies_to_codec() {
        let mut mgr = make_manager();
        mgr.open_session(SessionKind::Music, AudioRoute::Speaker)
            .ok();

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
            alarm.is_some_and(|s| s.active),
            "alarm must resume after call closes"
        );

        // Close alarm — music should resume.
        mgr.close_session(alarm_id).ok();
        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            music.is_some_and(|s| s.active),
            "music must resume after alarm closes"
        );

        // Close music — FM should resume.
        mgr.close_session(music_id).ok();
        let fm = mgr.active_sessions().iter().find(|s| s.id == fm_id);
        assert!(
            fm.is_some_and(|s| s.active),
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
            !fm.is_none_or(|s| s.active),
            "FM must be paused during ringtone"
        );

        // Close ringtone — FM resumes.
        mgr.close_session(ring_id).ok();
        let fm = mgr.active_sessions().iter().find(|s| s.id == fm_id);
        assert!(
            fm.is_some_and(|s| s.active),
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
        assert!(s.contains("42"), "display must include session ID");
        assert!(s.contains("music"), "display must include session kind");
        assert!(s.contains("active"), "display must include active state");
    }

    #[test]
    fn codec_operations_recorded_during_session_lifecycle() {
        let mut mgr = make_manager();

        // Open session — should power on, enable DAC, set volume, set output.
        mgr.open_session(SessionKind::Music, AudioRoute::Speaker)
            .ok();

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

    #[test]
    fn lower_priority_open_does_not_preempt_active_higher_priority() {
        // WHY: regression test for #386 — the preemption loop only paused
        // sessions at priority <= the new session's priority, so opening a
        // LOWER-priority session while a HIGHER-priority one was active
        // left both active and silently rerouted the codec to the new
        // session.
        let mut mgr = make_manager();

        let call_id = mgr
            .open_session(SessionKind::VoiceCall, AudioRoute::Earpiece)
            .unwrap_or(0);
        assert!(
            mgr.active_sessions()
                .iter()
                .find(|s| s.id == call_id)
                .is_some_and(|s| s.active),
            "voice call must be active"
        );

        // Open a lower-priority Music (Normal) session while the call is active.
        let music_id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);

        // The call must remain the sole active session and keep its route.
        let call = mgr.active_sessions().iter().find(|s| s.id == call_id);
        assert!(
            call.is_some_and(|s| s.active),
            "higher-priority call must remain active"
        );
        assert_eq!(
            mgr.active_route(),
            AudioRoute::Earpiece,
            "codec route must not be stolen by the lower-priority open (#386)"
        );

        // The new lower-priority session must be inserted paused, not active.
        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            !music.is_none_or(|s| s.active),
            "lower-priority session opened over an active higher-priority one must start paused"
        );

        // At most one session may be active.
        let active_count = mgr.active_sessions().iter().filter(|s| s.active).count();
        assert_eq!(
            active_count, 1,
            "at most one session may be active at a time"
        );

        // When the call closes, the paused Music session must resume.
        mgr.close_session(call_id).ok();
        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            music.is_some_and(|s| s.active),
            "music must resume once the call closes"
        );
    }

    #[test]
    fn open_session_enable_dac_failure_powers_off_codec() {
        // WHY: regression test for #390 — a failure partway through the
        // first-session hardware init sequence must not strand the codec
        // physically powered with no session recorded.
        let mut mgr = make_manager();
        mgr.codec_mut().fail_enable_dac = Some(AudioError::HardwareError);

        let result = mgr.open_session(SessionKind::Music, AudioRoute::Speaker);
        assert!(
            result.is_err(),
            "open_session must fail when enable_dac fails"
        );
        assert!(
            !mgr.is_codec_powered(),
            "codec must be powered off after a failed open_session (#390)"
        );
        assert_eq!(
            mgr.session_count(),
            0,
            "no session must be recorded on failure"
        );
    }

    #[test]
    fn open_session_mic_bias_failure_disables_adc() {
        // WHY: regression test for #390 — enable_mic_bias failing after
        // enable_adc succeeded must not leave the ADC live with
        // mgr.is_mic_powered() reporting false (an unobservable hot mic).
        let mut mgr = make_manager();
        mgr.codec_mut().fail_enable_mic_bias = Some(AudioError::HardwareError);

        let result = mgr.open_session(SessionKind::VoiceCall, AudioRoute::Earpiece);
        assert!(
            result.is_err(),
            "open_session must fail when enable_mic_bias fails"
        );
        assert!(
            !mgr.codec().is_adc_enabled(),
            "ADC must be rolled back when mic bias enable fails (#390)"
        );
        assert!(
            !mgr.is_mic_powered(),
            "mic must not be reported powered after a failed open_session"
        );
    }

    #[test]
    fn open_session_set_output_failure_preserves_preempted_sessions() {
        // WHY: regression test for #390 — a set_output failure during
        // preemption must not strand previously-active sessions paused
        // with no way to resume them.
        let mut mgr = make_manager();
        let music_id = mgr
            .open_session(SessionKind::Music, AudioRoute::Speaker)
            .unwrap_or(0);

        mgr.codec_mut().fail_set_output = Some(AudioError::HardwareError);
        let result = mgr.open_session(SessionKind::Alarm, AudioRoute::Speaker);
        assert!(
            result.is_err(),
            "open_session must fail when set_output fails"
        );

        let music = mgr.active_sessions().iter().find(|s| s.id == music_id);
        assert!(
            music.is_some_and(|s| s.active),
            "music must remain active when the preempting session's set_output fails (#390)"
        );
        assert_eq!(
            mgr.session_count(),
            1,
            "the failed session must not be recorded"
        );
    }

    #[test]
    fn power_down_mic_partial_failure_leaves_mic_powered_true_though_bias_already_off() {
        // WHY: pins a genuine gap -- power_down_mic calls
        // disable_mic_bias() then disable_adc(), each with `?`. If
        // disable_mic_bias() succeeds but disable_adc() fails, the method
        // returns before self.mic_powered is set false, so
        // mgr.is_mic_powered() keeps reporting true even though the
        // hardware mic bias is ALREADY off (only the ADC failed to power
        // down) -- a state/reality divergence in the exact invariant this
        // module's docs call "auditable via the session log" (#397).
        let mut mgr = make_manager();
        let call_id = mgr
            .open_session(SessionKind::VoiceCall, AudioRoute::Earpiece)
            .unwrap_or(0);
        assert!(
            mgr.is_mic_powered(),
            "mic must be powered during voice call"
        );

        mgr.codec_mut().fail_disable_adc = Some(AudioError::HardwareError);

        let result = mgr.close_session(call_id);
        assert!(
            result.is_err(),
            "close_session must propagate the disable_adc failure"
        );
        assert!(
            !mgr.codec().is_mic_bias_enabled(),
            "mic bias hardware must already be off -- disable_mic_bias \
             succeeded before disable_adc failed"
        );
        assert!(
            mgr.is_mic_powered(),
            "mgr.is_mic_powered() stays true because the `?` on the \
             failed disable_adc short-circuits before self.mic_powered is \
             set false -- this pins the current divergence, not asserted \
             here as desired behavior"
        );

        // Recovery: clear the fault and retry -- disable_mic_bias is
        // idempotent (MockCodec always succeeds and sets false), so the
        // retry only needs disable_adc to succeed this time.
        mgr.codec_mut().fail_disable_adc = None;
        let result = mgr.close_session(call_id);
        assert!(
            result.is_ok(),
            "retry must succeed once disable_adc recovers"
        );
        assert!(!mgr.is_mic_powered());
        assert_eq!(mgr.session_count(), 0);
    }
}
