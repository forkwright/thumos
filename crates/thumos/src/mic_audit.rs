//! Microphone usage audit log.
//!
//! Per the thumos security design, every microphone session must be logged
//! for user auditability.  This module provides a kernel-side audit trail
//! of all mic activations, recording:
//!
//! - Start and end ticks (kernel monotonic clock)
//! - Session kind (voice call, etc.)
//! - Caller identifier (module or subsystem that activated the mic)
//!
//! ## Access
//!
//! The audit log is accessible via the function search ("mic log") which
//! displays a list of recent mic sessions with timestamps and durations.
//! This gives the user full visibility into when and why the microphone
//! was active.
//!
//! ## Threat model
//!
//! The mic audit log defends against silent mic activation by rogue
//! kernel modules or compromised drivers.  Since all mic power gating
//! goes through `audio.rs` -> `audio_codec.rs` -> PMIC, and the audit
//! log is called from `audio.rs` on every mic power transition, any
//! mic activation that bypasses the audit log would also bypass the
//! PMIC and thus produce no audio.
//!
//! ## Integration
//!
//! Called from `audio.rs` (`AudioManager::open_session` / `close_session`)
//! when sessions with mic access (currently: `SessionKind::VoiceCall`)
//! are opened or closed.

// WHY: mic audit log not yet wired to audio manager (Wave 8, wiring pending).
#![expect(
    dead_code,
    reason = "Mic audit log created in Phase 07 Wave 8, audio manager wiring pending"
)]

extern crate alloc;
use alloc::vec::Vec;

use crate::audio_route::SessionKind;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of audit entries retained in memory.
///
/// When the log reaches this capacity, the oldest entry is dropped.
/// 256 entries covers approximately 256 voice calls, which is more than
/// enough for inspection.  Persistent storage (LFS) backing is future work.
const MAX_ENTRIES: usize = 256;

/// Maximum length of the caller identifier string.
const MAX_CALLER_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Mic audit log errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MicAuditError {
    /// The entry ID was not found in the log.
    EntryNotFound,
    /// The entry has already been ended.
    AlreadyEnded,
    /// The log is at capacity (should not happen with eviction, but defensive).
    LogFull,
}

impl core::fmt::Display for MicAuditError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EntryNotFound => write!(f, "audit entry not found"),
            Self::AlreadyEnded => write!(f, "audit entry already ended"),
            Self::LogFull => write!(f, "audit log full"),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit entry
// ---------------------------------------------------------------------------

/// A single microphone usage audit entry.
///
/// Records the start and end time of a mic session, the kind of audio
/// session that activated it, and an identifier for the calling subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicAuditEntry {
    /// Unique entry identifier (monotonically increasing).
    pub id: u32,
    /// Kernel tick (ms) when the mic was activated.
    pub start_tick: u64,
    /// Kernel tick (ms) when the mic was deactivated.
    ///
    /// `None` if the session is still active (mic is currently on). WHY
    /// (finding 7): a bare `u64` with `0` doubling as "active" made a
    /// session that genuinely ended at tick 0 (e.g. system boot), or a
    /// caller passing `0` to `log_end`, indistinguishable from "still
    /// running" -- `Option<u64>` has no such collision.
    pub end_tick: Option<u64>,
    /// Audio session kind that triggered mic activation.
    pub session_kind: SessionKind,
    /// Identifier of the calling subsystem (e.g., "telephony", "voip").
    pub caller: [u8; MAX_CALLER_LEN],
    /// Number of valid bytes in `caller`.
    pub caller_len: u8,
}

impl MicAuditEntry {
    /// Return the caller identifier as a byte slice.
    #[must_use]
    pub(crate) fn caller(&self) -> &[u8] {
        &self.caller[..self.caller_len as usize]
    }

    /// Return whether this session is still active (mic is on).
    #[must_use]
    pub(crate) fn is_active(&self) -> bool {
        self.end_tick.is_none()
    }

    /// Return the duration of the session in milliseconds.
    ///
    /// Returns `None` if the session is still active.
    #[must_use]
    pub(crate) fn duration_ms(&self) -> Option<u64> {
        self.end_tick.map(|end| end.saturating_sub(self.start_tick))
    }
}

impl core::fmt::Display for MicAuditEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let caller_str = core::str::from_utf8(self.caller()).unwrap_or("?");
        match self.duration_ms() {
            Some(duration) => {
                let secs = duration / 1000;
                let mins = secs / 60;
                let remaining_secs = secs % 60;
                write!(
                    f,
                    "[{}] {} ({}) {}m{}s",
                    self.id, self.session_kind, caller_str, mins, remaining_secs,
                )
            }
            None => {
                write!(
                    f,
                    "[{}] {} ({}) ACTIVE",
                    self.id, self.session_kind, caller_str,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// Microphone usage audit log.
///
/// Maintains an ordered list of mic activation entries.  When the log
/// reaches `MAX_ENTRIES`, the oldest entry is evicted.
pub(crate) struct MicAuditLog {
    /// Audit entries, ordered by `start_tick` (oldest first).
    entries: Vec<MicAuditEntry>,
    /// Next entry ID to allocate.
    next_id: u32,
}

impl MicAuditLog {
    /// Create a new, empty audit log.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::with_capacity(64),
            next_id: 1,
        }
    }

    /// Log the start of a mic session.
    ///
    /// Returns the entry ID, which must be passed to `log_end()` when
    /// the session concludes.
    pub(crate) fn log_start(&mut self, kind: SessionKind, caller: &[u8], tick_ms: u64) -> u32 {
        // Evict oldest if at capacity.
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.remove(0);
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let mut caller_buf = [0u8; MAX_CALLER_LEN];
        let copy_len = caller.len().min(MAX_CALLER_LEN);
        caller_buf[..copy_len].copy_from_slice(&caller[..copy_len]);

        let entry = MicAuditEntry {
            id,
            start_tick: tick_ms,
            end_tick: None,
            session_kind: kind,
            caller: caller_buf,
            caller_len: copy_len as u8,
        };
        self.entries.push(entry);

        id
    }

    /// Log the end of a mic session.
    ///
    /// Records the end tick for the entry with the given ID.
    pub(crate) fn log_end(&mut self, entry_id: u32, tick_ms: u64) -> Result<(), MicAuditError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == entry_id)
            .ok_or(MicAuditError::EntryNotFound)?;

        if !entry.is_active() {
            return Err(MicAuditError::AlreadyEnded);
        }

        entry.end_tick = Some(tick_ms);
        Ok(())
    }

    /// Return all audit entries (oldest first).
    #[must_use]
    pub(crate) fn entries(&self) -> &[MicAuditEntry] {
        &self.entries
    }

    /// Return the N most recent audit entries.
    ///
    /// Returns at most `n` entries from the end of the log.
    #[must_use]
    pub(crate) fn recent(&self, n: usize) -> &[MicAuditEntry] {
        let len = self.entries.len();
        if n >= len {
            &self.entries
        } else {
            &self.entries[len - n..]
        }
    }

    /// Return the total number of entries in the log.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the log is empty.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return any currently active (mic-on) entries.
    #[must_use]
    pub(crate) fn active_sessions(&self) -> Vec<&MicAuditEntry> {
        self.entries.iter().filter(|e| e.is_active()).collect()
    }

    /// Check whether any mic session is currently active.
    #[must_use]
    pub(crate) fn is_mic_active(&self) -> bool {
        self.entries.iter().any(MicAuditEntry::is_active)
    }

    /// Clear all entries from the log.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_start_creates_entry() {
        let mut log = MicAuditLog::new();
        let id = log.log_start(SessionKind::VoiceCall, b"telephony", 1000);
        assert_eq!(id, 1, "first entry ID must be 1");
        assert_eq!(log.len(), 1, "log must contain 1 entry");

        let entry = &log.entries()[0];
        assert_eq!(entry.id, 1);
        assert_eq!(entry.start_tick, 1000);
        assert_eq!(
            entry.end_tick, None,
            "active session must have end_tick None"
        );
        assert_eq!(entry.session_kind, SessionKind::VoiceCall);
        assert_eq!(entry.caller(), b"telephony");
        assert!(entry.is_active(), "entry must be active before log_end");
    }

    #[test]
    fn log_end_records_duration() {
        let mut log = MicAuditLog::new();
        let id = log.log_start(SessionKind::VoiceCall, b"telephony", 1000);
        let result = log.log_end(id, 5000);
        assert!(result.is_ok(), "log_end must succeed");

        let entry = &log.entries()[0];
        assert_eq!(entry.end_tick, Some(5000));
        assert!(!entry.is_active(), "entry must not be active after log_end");
        assert_eq!(
            entry.duration_ms(),
            Some(4000),
            "duration must be end - start = 4000ms"
        );
    }

    #[test]
    fn log_end_nonexistent_entry() {
        let mut log = MicAuditLog::new();
        let result = log.log_end(999, 5000);
        assert_eq!(
            result,
            Err(MicAuditError::EntryNotFound),
            "ending nonexistent entry must return EntryNotFound"
        );
    }

    #[test]
    fn log_end_already_ended() {
        let mut log = MicAuditLog::new();
        let id = log.log_start(SessionKind::VoiceCall, b"telephony", 1000);
        log.log_end(id, 2000).ok();

        let result = log.log_end(id, 3000);
        assert_eq!(
            result,
            Err(MicAuditError::AlreadyEnded),
            "ending an already-ended entry must return AlreadyEnded"
        );
    }

    #[test]
    fn log_end_at_tick_zero_is_not_confused_with_active() {
        // finding 7: a session that legitimately ends at tick 0 must not
        // be reported as still active -- the old end_tick: u64 sentinel
        // (0 == "active") made this ambiguous. end_tick: Option<u64> has
        // no such collision.
        let mut log = MicAuditLog::new();
        let id = log.log_start(SessionKind::VoiceCall, b"telephony", 0);
        log.log_end(id, 0).ok();

        let entry = &log.entries()[0];
        assert!(
            !entry.is_active(),
            "a session ended at tick 0 must not read as active"
        );
        assert_eq!(entry.end_tick, Some(0));
        assert_eq!(entry.duration_ms(), Some(0));
    }

    #[test]
    fn recent_returns_latest() {
        let mut log = MicAuditLog::new();
        log.log_start(SessionKind::VoiceCall, b"call1", 1000);
        log.log_start(SessionKind::VoiceCall, b"call2", 2000);
        log.log_start(SessionKind::VoiceCall, b"call3", 3000);

        let recent = log.recent(2);
        assert_eq!(recent.len(), 2, "recent(2) must return 2 entries");
        assert_eq!(
            recent[0].caller(),
            b"call2",
            "first recent entry must be second-to-last"
        );
        assert_eq!(
            recent[1].caller(),
            b"call3",
            "second recent entry must be the last"
        );
    }

    #[test]
    fn recent_more_than_total() {
        let mut log = MicAuditLog::new();
        log.log_start(SessionKind::VoiceCall, b"call1", 1000);

        let recent = log.recent(10);
        assert_eq!(
            recent.len(),
            1,
            "recent(10) with 1 entry must return all 1 entry"
        );
    }

    #[test]
    fn entries_ordered_by_time() {
        let mut log = MicAuditLog::new();
        log.log_start(SessionKind::VoiceCall, b"a", 100);
        log.log_start(SessionKind::VoiceCall, b"b", 200);
        log.log_start(SessionKind::VoiceCall, b"c", 300);

        let entries = log.entries();
        assert_eq!(entries.len(), 3);
        assert!(
            entries[0].start_tick < entries[1].start_tick,
            "entries must be ordered by start_tick"
        );
        assert!(
            entries[1].start_tick < entries[2].start_tick,
            "entries must be ordered by start_tick"
        );
    }

    #[test]
    fn active_sessions_tracked() {
        let mut log = MicAuditLog::new();
        let id1 = log.log_start(SessionKind::VoiceCall, b"call1", 1000);
        let id2 = log.log_start(SessionKind::VoiceCall, b"call2", 2000);

        assert!(log.is_mic_active(), "mic must be active with open sessions");
        assert_eq!(log.active_sessions().len(), 2);

        log.log_end(id1, 3000).ok();
        assert!(
            log.is_mic_active(),
            "mic must still be active with one open session"
        );
        assert_eq!(log.active_sessions().len(), 1);

        log.log_end(id2, 4000).ok();
        assert!(
            !log.is_mic_active(),
            "mic must not be active with no open sessions"
        );
        assert_eq!(log.active_sessions().len(), 0);
    }

    #[test]
    fn ids_increment() {
        let mut log = MicAuditLog::new();
        let id1 = log.log_start(SessionKind::VoiceCall, b"a", 100);
        let id2 = log.log_start(SessionKind::VoiceCall, b"b", 200);
        let id3 = log.log_start(SessionKind::VoiceCall, b"c", 300);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    #[test]
    fn eviction_at_capacity() {
        let mut log = MicAuditLog::new();
        for i in 0..MAX_ENTRIES {
            log.log_start(SessionKind::VoiceCall, b"x", i as u64 * 100);
        }
        assert_eq!(log.len(), MAX_ENTRIES);

        // Adding one more should evict the oldest.
        log.log_start(SessionKind::VoiceCall, b"newest", 99999);
        assert_eq!(log.len(), MAX_ENTRIES, "log must not exceed MAX_ENTRIES");
        // Oldest entry (start_tick=0) should be gone.
        assert_ne!(
            log.entries()[0].start_tick,
            0,
            "oldest entry must have been evicted"
        );
    }

    #[test]
    fn caller_truncation() {
        let mut log = MicAuditLog::new();
        let long_caller = [b'A'; 64]; // longer than MAX_CALLER_LEN
        let id = log.log_start(SessionKind::VoiceCall, &long_caller, 1000);

        let entry = &log.entries()[0];
        assert_eq!(
            entry.caller_len as usize, MAX_CALLER_LEN,
            "caller must be truncated to MAX_CALLER_LEN"
        );
        assert_eq!(
            entry.caller(),
            &[b'A'; MAX_CALLER_LEN],
            "truncated caller must contain the first MAX_CALLER_LEN bytes"
        );
        let _ = id;
    }

    #[test]
    fn clear_empties_log() {
        let mut log = MicAuditLog::new();
        log.log_start(SessionKind::VoiceCall, b"test", 1000);
        log.log_start(SessionKind::VoiceCall, b"test", 2000);
        assert_eq!(log.len(), 2);

        log.clear();
        assert!(log.is_empty(), "log must be empty after clear");
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn entry_display_active() {
        let mut log = MicAuditLog::new();
        log.log_start(SessionKind::VoiceCall, b"telephony", 1000);
        let entry = &log.entries()[0];
        let display = alloc::format!("{entry}");
        assert!(display.contains("ACTIVE"), "active entry must show ACTIVE");
        assert!(display.contains("telephony"), "display must include caller");
    }

    #[test]
    fn entry_display_completed() {
        let mut log = MicAuditLog::new();
        let id = log.log_start(SessionKind::VoiceCall, b"telephony", 1000);
        log.log_end(id, 61_000).ok(); // 60 seconds = 1m0s

        let entry = &log.entries()[0];
        let display = alloc::format!("{entry}");
        assert!(
            display.contains("1m0s"),
            "completed entry must show duration: {display}"
        );
    }

    #[test]
    fn empty_log_queries() {
        let log = MicAuditLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(!log.is_mic_active());
        assert_eq!(log.entries().len(), 0);
        assert_eq!(log.recent(5).len(), 0);
        assert_eq!(log.active_sessions().len(), 0);
    }

    #[test]
    fn log_full_error_variant() {
        // MicAuditError::LogFull is a defensive variant -- the current
        // implementation evicts oldest entries rather than returning LogFull.
        // This test verifies the variant is constructable and displays correctly.
        let err = MicAuditError::LogFull;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "audit log full", "LogFull display must match");
        assert_eq!(err, MicAuditError::LogFull, "LogFull must be Eq");
    }
}
