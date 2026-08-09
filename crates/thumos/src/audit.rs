//! Tamper-evident HMAC-chain audit log for security events.
//!
//! Provides a fixed-size 64 KiB ring buffer of audit entries, where each
//! entry carries an HMAC-SHA256 covering its content concatenated with
//! the previous entry's HMAC.  This chaining guarantees that any single
//! tampered entry invalidates the entire chain from that point forward.
//!
//! ## Event types
//!
//! The audit log records security-relevant kernel events:
//!
//! - `AuthFail` — failed authentication attempt (passphrase/PIN)
//! - `CapDeny` — capability check denial
//! - `PacketDeny` — firewall packet rejection
//! - `PanicTrigger` — panic mode activation
//! - `IdentityLeak` — potential identity information leak detected
//! - `SwitchChange` — hardware kill switch state change
//! - `BootVerify` — measured boot signature verification result
//! - `ModeChange` — security mode transition (Daily/Sentinel/Panic)
//! - `DuressAttempt` — duress PIN entry detected
//!
//! ## HMAC key
//!
//! The HMAC key is derived from the key hierarchy's audit sub-key
//! (`key_manager.audit_key()`), which uses the HKDF label
//! `"thumos-audit-v1"`.  This key survives selective wipe (only
//! zeroized on full panic or long-sleep), allowing the chain to be
//! verified after partial data purges.
//!
//! ## Ring buffer
//!
//! The buffer holds a fixed number of entries (computed from a 64 KiB
//! budget divided by the entry size).  When the buffer is full, the
//! oldest entry is overwritten.  The HMAC chain remains valid for all
//! entries currently in the ring; verification starts from the oldest
//! live entry.
//!
//! ## Integration points
//!
//! - `capability.rs` — `CapDeny` events
//! - `firewall.rs` — `PacketDeny` events
//! - `lock_screen.rs` — `AuthFail`, `DuressAttempt` events
//! - `security_mode.rs` — `ModeChange`, `PanicTrigger` events
//! - `secure_boot.rs` (Wave 6) — `BootVerify` events

use core::fmt;

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use subtle::ConstantTimeEq;

use crate::security::{self, KEY_SIZE, SHA256_DIGEST_LEN};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Total audit buffer budget in bytes (64 KiB).
const BUFFER_SIZE: usize = 64 * 1024;

/// Maximum number of entries that fit in the buffer.
///
/// Computed at compile time from the entry size and the 64 KiB budget.
const MAX_ENTRIES: usize = BUFFER_SIZE / core::mem::size_of::<AuditEntry>();

/// Size of the fixed-length detail field in each audit entry.
pub(crate) const DETAIL_LEN: usize = 64;

/// Initial HMAC value for the first entry in the chain (all zeros).
///
/// The genesis entry chains from this sentinel so that `verify_chain`
/// has a uniform algorithm with no special-case for the first entry.
const GENESIS_HMAC: [u8; SHA256_DIGEST_LEN] = [0u8; SHA256_DIGEST_LEN];

// ---------------------------------------------------------------------------
// AuditEventType
// ---------------------------------------------------------------------------

/// Security event types recorded in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum AuditEventType {
    /// Failed authentication attempt (passphrase or PIN).
    AuthFail,
    /// Capability check denied.
    CapDeny,
    /// Firewall packet denied.
    PacketDeny,
    /// Panic mode activated.
    PanicTrigger,
    /// Potential identity information leak detected.
    IdentityLeak,
    /// Hardware kill switch state changed.
    SwitchChange,
    /// Measured boot verification result.
    BootVerify,
    /// Security mode transition.
    ModeChange,
    /// Duress PIN entry detected.
    DuressAttempt,
    /// Modem traffic anomaly detected by CCCI baseline comparison.
    ModemAnomaly,
    /// Modem traffic event logged by CCCI firewall.
    ModemTraffic,
    /// Firewall packet forwarded and logged by a `Log`-actioned rule (#403).
    PacketLog,
    /// A PL0 process faulted and was killed (#492). Logged by the PID-0 fault
    /// supervisor for EVERY fault report, supervised service or not.
    UserFault,
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFail => write!(f, "AUTH_FAIL"),
            Self::CapDeny => write!(f, "CAP_DENY"),
            Self::PacketDeny => write!(f, "PACKET_DENY"),
            Self::PanicTrigger => write!(f, "PANIC_TRIGGER"),
            Self::IdentityLeak => write!(f, "IDENTITY_LEAK"),
            Self::SwitchChange => write!(f, "SWITCH_CHANGE"),
            Self::BootVerify => write!(f, "BOOT_VERIFY"),
            Self::ModeChange => write!(f, "MODE_CHANGE"),
            Self::DuressAttempt => write!(f, "DURESS_ATTEMPT"),
            Self::ModemAnomaly => write!(f, "MODEM_ANOMALY"),
            Self::ModemTraffic => write!(f, "MODEM_TRAFFIC"),
            Self::PacketLog => write!(f, "PACKET_LOG"),
            Self::UserFault => write!(f, "USER_FAULT"),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditEntry
// ---------------------------------------------------------------------------

/// A single tamper-evident audit log entry.
///
/// Each entry records a security event with a monotonic timestamp,
/// the originating process ID, a fixed-size detail field, and an
/// HMAC-SHA256 covering (content || previous HMAC) to form a hash chain.
#[derive(Clone)]
#[must_use]
pub struct AuditEntry {
    /// Monotonic timestamp (kernel ticks, milliseconds).
    pub timestamp: u64,
    /// Security event type.
    pub event_type: AuditEventType,
    /// Process ID that triggered the event (0 for kernel context).
    pub pid: u32,
    /// Fixed-size detail string (null-padded).
    pub detail: [u8; DETAIL_LEN],
    /// Number of valid bytes in `detail`.
    pub detail_len: u8,
    /// HMAC-SHA256 covering (timestamp || `event_type` || pid || detail || `prev_hmac`).
    pub hmac: [u8; SHA256_DIGEST_LEN],
}

impl AuditEntry {
    /// Return the detail field as a byte slice (only valid bytes).
    #[must_use]
    pub(crate) fn detail(&self) -> &[u8] {
        &self.detail[..self.detail_len as usize]
    }

    /// Serialize the entry content (excluding the HMAC itself) into a
    /// buffer suitable for HMAC computation.
    ///
    /// Layout: timestamp (8 LE) || `event_type` (1) || pid (4 LE) || detail (64) || `prev_hmac` (32)
    ///
    /// Returns the number of bytes written.
    fn serialize_for_hmac(
        &self,
        prev_hmac: &[u8; SHA256_DIGEST_LEN],
        buf: &mut [u8; 109],
    ) -> usize {
        let mut offset = 0;

        // Timestamp: 8 bytes little-endian.
        buf[offset..offset + 8].copy_from_slice(&self.timestamp.to_le_bytes());
        offset += 8;

        // Event type: 1 byte discriminant.
        buf[offset] = event_type_discriminant(self.event_type);
        offset += 1;

        // PID: 4 bytes little-endian.
        buf[offset..offset + 4].copy_from_slice(&self.pid.to_le_bytes());
        offset += 4;

        // Detail: full 64-byte field (including padding zeros).
        buf[offset..offset + DETAIL_LEN].copy_from_slice(&self.detail);
        offset += DETAIL_LEN;

        // Previous HMAC: 32 bytes.
        buf[offset..offset + SHA256_DIGEST_LEN].copy_from_slice(prev_hmac);
        offset += SHA256_DIGEST_LEN;

        offset
    }
}

impl fmt::Debug for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEntry")
            .field("timestamp", &self.timestamp)
            .field("event_type", &self.event_type)
            .field("pid", &self.pid)
            .field("detail_len", &self.detail_len)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AuditEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[t={} pid={} {}] ",
            self.timestamp, self.pid, self.event_type,
        )?;
        // WHY: non-UTF8 detail bytes previously collapsed to a single "?"
        // via str::from_utf8(...).unwrap_or("?"), erasing the audit
        // content entirely. Render every byte instead: printable ASCII
        // as-is, everything else \xHH-escaped, so no content is lost.
        for &byte in self.detail() {
            if byte.is_ascii_graphic() || byte == b' ' {
                write!(f, "{}", char::from(byte))?;
            } else {
                write!(f, "\\x{byte:02x}")?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper: event type discriminant
// ---------------------------------------------------------------------------

/// Map an `AuditEventType` to a stable u8 discriminant for serialization.
///
/// These values are part of the on-disk/HMAC format and must never change
/// for existing variants.
const fn event_type_discriminant(event: AuditEventType) -> u8 {
    match event {
        AuditEventType::AuthFail => 0,
        AuditEventType::CapDeny => 1,
        AuditEventType::PacketDeny => 2,
        AuditEventType::PanicTrigger => 3,
        AuditEventType::IdentityLeak => 4,
        AuditEventType::SwitchChange => 5,
        AuditEventType::BootVerify => 6,
        AuditEventType::ModeChange => 7,
        AuditEventType::DuressAttempt => 8,
        AuditEventType::ModemAnomaly => 9,
        AuditEventType::ModemTraffic => 10,
        // WHY append-only: discriminants are stable wire/HMAC identifiers -- a
        // new variant takes the next integer; existing values never change.
        AuditEventType::PacketLog => 11,
        AuditEventType::UserFault => 12,
    }
}

// ---------------------------------------------------------------------------
// AuditError
// ---------------------------------------------------------------------------

/// Errors from audit log operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum AuditError {
    /// No HMAC key is available (key manager has no audit key loaded).
    NoKey,
    /// The HMAC chain verification detected tampering.
    ChainTampered,
    /// The audit log is empty (nothing to verify).
    Empty,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoKey => write!(f, "audit HMAC key not available"),
            Self::ChainTampered => write!(f, "HMAC chain verification failed: tampering detected"),
            Self::Empty => write!(f, "audit log is empty"),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------

/// Tamper-evident HMAC-chain audit log.
///
/// Uses a fixed-size ring buffer of [`MAX_ENTRIES`] entries (fitting within
/// a 64 KiB budget).  Each entry's HMAC chains from the previous entry,
/// forming a tamper-evident sequence.
///
/// The ring buffer overwrites the oldest entry when full.  The `head`
/// index tracks the next write position, and `count` tracks how many
/// entries are live (up to `MAX_ENTRIES`).
// INVARIANT: `entries` is heap-allocated (`Box<[AuditEntry]>`), never an
// inline `[AuditEntry; MAX_ENTRIES]` array. MAX_ENTRIES * size_of::<AuditEntry>()
// is ~64 KiB; an inline array field would make `AuditLog` itself ~64 KiB and
// risk a stack overflow the moment a caller binds `AuditLog::new()` to a
// local on the 64 KiB MT6739 boot stack (#297).
#[must_use]
pub(crate) struct AuditLog {
    /// Ring buffer of audit entries (heap-allocated; see struct INVARIANT).
    entries: Box<[AuditEntry]>,
    /// Index of the next write position in the ring.
    head: usize,
    /// Number of live entries (`0..=MAX_ENTRIES`).
    count: usize,
    /// HMAC of the most recently appended entry (chains the next append).
    last_hmac: [u8; SHA256_DIGEST_LEN],
    /// HMAC that chains into the current oldest live entry. Equal to
    /// `GENESIS_HMAC` until the ring first wraps; from then on it holds
    /// the HMAC of the entry evicted to make room for the current
    /// oldest entry, captured by `log_event` at eviction time, so
    /// `verify_chain` can validate the oldest live entry after wrap
    /// instead of trusting it unchecked.
    root_hmac: [u8; SHA256_DIGEST_LEN],
}

impl AuditLog {
    /// Create a new, empty audit log.
    ///
    /// `entries` is built element-by-element into a heap-allocated `Vec`
    /// and converted to a boxed slice, so the ~64 KiB backing storage is
    /// never materialized as a single stack frame (#297).
    pub(crate) fn new() -> Self {
        let mut entries = Vec::with_capacity(MAX_ENTRIES);
        for _ in 0..MAX_ENTRIES {
            entries.push(AuditEntry {
                timestamp: 0,
                event_type: AuditEventType::AuthFail,
                pid: 0,
                detail: [0u8; DETAIL_LEN],
                detail_len: 0,
                hmac: [0u8; SHA256_DIGEST_LEN],
            });
        }
        Self {
            entries: entries.into_boxed_slice(),
            head: 0,
            count: 0,
            last_hmac: GENESIS_HMAC,
            root_hmac: GENESIS_HMAC,
        }
    }

    /// Append a security event to the audit log.
    ///
    /// Computes an HMAC-SHA256 covering the entry content concatenated
    /// with the previous entry's HMAC, forming a tamper-evident chain.
    ///
    /// # Arguments
    ///
    /// - `event_type` — the security event category
    /// - `pid` — process ID that triggered the event (0 for kernel)
    /// - `detail` — human-readable detail (truncated to [`DETAIL_LEN`] bytes)
    /// - `timestamp` — monotonic kernel tick (milliseconds)
    /// - `hmac_key` — the 32-byte audit HMAC key from the key manager
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::NoKey`] if `hmac_key` is empty (all zeros).
    pub(crate) fn log_event(
        &mut self,
        event_type: AuditEventType,
        pid: u32,
        detail: &[u8],
        timestamp: u64,
        hmac_key: &[u8; KEY_SIZE],
    ) -> Result<(), AuditError> {
        // Reject all-zero key (indicates key not loaded).
        if hmac_key.iter().all(|&b| b == 0) {
            return Err(AuditError::NoKey);
        }

        // Build the entry.
        let mut detail_buf = [0u8; DETAIL_LEN];
        let copy_len = detail.len().min(DETAIL_LEN);
        detail_buf[..copy_len].copy_from_slice(&detail[..copy_len]);

        let mut entry = AuditEntry {
            timestamp,
            event_type,
            pid,
            detail: detail_buf,
            detail_len: copy_len as u8,
            hmac: [0u8; SHA256_DIGEST_LEN],
        };

        // Compute HMAC over (content || prev_hmac).
        let mut serialized = [0u8; 109];
        let len = entry.serialize_for_hmac(&self.last_hmac, &mut serialized);
        let hmac = security::hmac_sha256(hmac_key, &serialized[..len]);
        entry.hmac = hmac;

        // Write into the ring buffer. If the ring is already full, this
        // write evicts the current oldest entry; capture its HMAC as the
        // new chain root so verify_chain can still validate the new
        // oldest entry (which chained from the evicted one) after wrap.
        if self.count == MAX_ENTRIES {
            self.root_hmac = self.entries[self.head].hmac;
        }
        self.entries[self.head] = entry;
        self.head = (self.head + 1) % MAX_ENTRIES;
        if self.count < MAX_ENTRIES {
            self.count += 1;
        }

        self.last_hmac = hmac;
        Ok(())
    }

    /// Verify the HMAC chain integrity of all live entries.
    ///
    /// Walks the entries from oldest to newest, recomputing each HMAC
    /// from (content || previous HMAC) and comparing against the stored
    /// HMAC.  Any mismatch indicates tampering.
    ///
    /// # Ring buffer wrap
    ///
    /// After a ring buffer wrap, the true genesis HMAC (all zeros) is no
    /// longer the chain root for the oldest live entry -- that entry
    /// chained from whatever occupied its slot before eviction.
    /// `log_event` captures the evicted entry's HMAC into `root_hmac`
    /// before overwriting it, so verification always has a real
    /// (non-trusted) root to check the oldest live entry against; no
    /// entry is ever skipped or trusted unchecked.
    ///
    /// # Errors
    ///
    /// - [`AuditError::Empty`] if the log has no entries.
    /// - [`AuditError::NoKey`] if `hmac_key` is all zeros.
    /// - [`AuditError::ChainTampered`] if any entry's HMAC does not match.
    pub(crate) fn verify_chain(&self, hmac_key: &[u8; KEY_SIZE]) -> Result<(), AuditError> {
        if self.count == 0 {
            return Err(AuditError::Empty);
        }
        if hmac_key.iter().all(|&b| b == 0) {
            return Err(AuditError::NoKey);
        }

        let wrapped = self.count == MAX_ENTRIES;

        // Starting index of the oldest live entry.
        let start = if wrapped { self.head } else { 0 };

        // Determine the previous HMAC for the first entry in the chain.
        // If the buffer has not wrapped, the genesis HMAC is all zeros.
        // If wrapped, `root_hmac` holds the HMAC of the entry that was
        // evicted to make room for the current oldest live entry
        // (captured in `log_event`), so every live entry -- including
        // the oldest -- is verified below; none are trusted unchecked.
        let mut prev_hmac = if wrapped {
            self.root_hmac
        } else {
            GENESIS_HMAC
        };

        for i in 0..self.count {
            let idx = (start + i) % MAX_ENTRIES;
            let entry = &self.entries[idx];

            let mut serialized = [0u8; 109];
            let len = entry.serialize_for_hmac(&prev_hmac, &mut serialized);
            let expected = security::hmac_sha256(hmac_key, &serialized[..len]);

            // WHY: constant-time compare — a variable-time `!=` on the HMAC
            // leaks, via timing, how many leading bytes matched, aiding forgery
            // of a tampered chain. `subtle::ConstantTimeEq` compares all bytes.
            if entry.hmac[..].ct_eq(&expected[..]).unwrap_u8() == 0 {
                return Err(AuditError::ChainTampered);
            }

            prev_hmac = entry.hmac;
        }

        Ok(())
    }

    /// Return the `n` most recent audit entries.
    ///
    /// Returns a pair of slices `(older, newer)` that together contain
    /// at most `n` entries in chronological order.  The two-slice return
    /// is due to the ring buffer potentially wrapping around the backing
    /// array.
    ///
    /// To iterate in order: process `older` first, then `newer`.
    pub(crate) fn recent(&self, n: usize) -> (&[AuditEntry], &[AuditEntry]) {
        if self.count == 0 || n == 0 {
            return (&[], &[]);
        }

        let n = n.min(self.count);

        // The most recent entry is at (head - 1) in the ring.
        // The oldest of the requested N is at (head - n).
        let start = if self.head >= n {
            self.head - n
        } else if self.count == MAX_ENTRIES {
            // Wrapped: start is in the upper portion of the array.
            MAX_ENTRIES - (n - self.head)
        } else {
            // Not wrapped, fewer than n entries exist (clamped above).
            0
        };

        let end = self.head;

        if start < end {
            // Contiguous slice.
            (&self.entries[start..end], &[])
        } else {
            // Wraps around: return two slices.
            (&self.entries[start..MAX_ENTRIES], &self.entries[..end])
        }
    }

    /// Return the number of live entries in the log.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.count
    }

    /// Return whether the log is empty.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return whether the ring buffer has wrapped (oldest entries overwritten).
    #[must_use]
    pub(crate) fn has_wrapped(&self) -> bool {
        self.count == MAX_ENTRIES
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLog")
            .field("count", &self.count)
            .field("head", &self.head)
            .field("max_entries", &MAX_ENTRIES)
            .field("has_wrapped", &self.has_wrapped())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for AuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuditLog({}/{} entries{})",
            self.count,
            MAX_ENTRIES,
            if self.has_wrapped() { ", wrapped" } else { "" },
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    /// Test HMAC key (non-zero, deterministic).
    const TEST_KEY: [u8; KEY_SIZE] = [0xAA; KEY_SIZE];

    /// Append a single audit event for use in test assertions.
    fn log_one(log: &mut AuditLog, event_type: AuditEventType, pid: u32, detail: &[u8], tick: u64) {
        log.log_event(event_type, pid, detail, tick, &TEST_KEY)
            .expect("log_event failed in test");
    }

    // -- Chain integrity tests --

    #[test]
    fn chain_validates_clean() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::AuthFail, 1, b"wrong PIN", 100);
        log_one(&mut log, AuditEventType::CapDeny, 2, b"no NET cap", 200);
        log_one(
            &mut log,
            AuditEventType::ModeChange,
            0,
            b"Daily->Sentinel",
            300,
        );

        let result = log.verify_chain(&TEST_KEY);
        assert!(result.is_ok(), "clean chain must verify: {result:?}");
    }

    #[test]
    fn chain_detects_single_entry_tamper() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::AuthFail, 1, b"attempt 1", 100);
        log_one(&mut log, AuditEventType::AuthFail, 1, b"attempt 2", 200);
        log_one(&mut log, AuditEventType::AuthFail, 1, b"attempt 3", 300);

        // Tamper with the middle entry's detail field.
        log.entries[1].detail[0] = 0xFF;

        let result = log.verify_chain(&TEST_KEY);
        assert_eq!(
            result,
            Err(AuditError::ChainTampered),
            "tampered entry must be detected"
        );
    }

    #[test]
    fn chain_detects_timestamp_tamper() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::BootVerify, 0, b"ok", 100);
        log_one(&mut log, AuditEventType::ModeChange, 0, b"Daily", 200);

        // Tamper with the second entry's timestamp.
        log.entries[1].timestamp = 999;

        let result = log.verify_chain(&TEST_KEY);
        assert_eq!(
            result,
            Err(AuditError::ChainTampered),
            "timestamp tamper must be detected"
        );
    }

    #[test]
    fn chain_detects_hmac_tamper() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::PacketDeny, 5, b"blocked", 100);
        log_one(&mut log, AuditEventType::PacketDeny, 5, b"blocked2", 200);

        // Tamper with the first entry's HMAC directly.
        log.entries[0].hmac[0] ^= 0xFF;

        let result = log.verify_chain(&TEST_KEY);
        assert_eq!(
            result,
            Err(AuditError::ChainTampered),
            "HMAC tamper must be detected"
        );
    }

    // -- Ring buffer wrap tests --

    #[test]
    fn ring_buffer_wraps() {
        let mut log = AuditLog::new();

        // Fill the buffer completely.
        for i in 0..MAX_ENTRIES {
            log_one(
                &mut log,
                AuditEventType::PacketDeny,
                i as u32,
                b"fill",
                i as u64 * 10,
            );
        }
        assert_eq!(log.len(), MAX_ENTRIES, "buffer must be full");
        assert!(log.has_wrapped(), "buffer must have wrapped");

        // Add one more — should overwrite the oldest.
        log_one(&mut log, AuditEventType::AuthFail, 9999, b"overflow", 99999);
        assert_eq!(
            log.len(),
            MAX_ENTRIES,
            "count must stay at MAX_ENTRIES after wrap"
        );

        // The chain should still verify (with wrapped semantics).
        let result = log.verify_chain(&TEST_KEY);
        assert!(result.is_ok(), "chain must verify after wrap: {result:?}");
    }

    #[test]
    fn ring_buffer_wraps_multiple_times() {
        let mut log = AuditLog::new();

        // Fill 3x the capacity.
        for i in 0..(MAX_ENTRIES * 3) {
            log_one(
                &mut log,
                AuditEventType::CapDeny,
                i as u32,
                b"multi-wrap",
                i as u64,
            );
        }
        assert_eq!(log.len(), MAX_ENTRIES);
        assert!(log.has_wrapped());

        let result = log.verify_chain(&TEST_KEY);
        assert!(
            result.is_ok(),
            "chain must verify after multiple wraps: {result:?}"
        );
    }

    #[test]
    fn chain_detects_oldest_entry_tamper_after_wrap() {
        let mut log = AuditLog::new();

        // Fill the buffer completely, then wrap once so the oldest live
        // entry (at ring index `log.head`) chained from an entry that
        // was evicted, not from the genesis HMAC.
        for i in 0..MAX_ENTRIES {
            log_one(
                &mut log,
                AuditEventType::PacketDeny,
                i as u32,
                b"fill",
                i as u64 * 10,
            );
        }
        log_one(&mut log, AuditEventType::AuthFail, 9999, b"overflow", 99999);
        assert!(log.has_wrapped());

        // Tamper with the new oldest live entry (index `log.head`) --
        // exactly the entry the pre-fix code trusted unconditionally
        // instead of verifying.
        let oldest_idx = log.head;
        log.entries[oldest_idx].detail[0] ^= 0xFF;

        let result = log.verify_chain(&TEST_KEY);
        assert_eq!(
            result,
            Err(AuditError::ChainTampered),
            "tampering the oldest live entry after a ring-buffer wrap must be detected, not trusted (pre-fix: this returned Ok)"
        );
    }

    // -- Event type coverage --

    #[test]
    fn all_event_types_recorded() {
        let mut log = AuditLog::new();
        let event_types = [
            AuditEventType::AuthFail,
            AuditEventType::CapDeny,
            AuditEventType::PacketDeny,
            AuditEventType::PanicTrigger,
            AuditEventType::IdentityLeak,
            AuditEventType::SwitchChange,
            AuditEventType::BootVerify,
            AuditEventType::ModeChange,
            AuditEventType::DuressAttempt,
            AuditEventType::ModemAnomaly,
            AuditEventType::ModemTraffic,
            AuditEventType::PacketLog,
            AuditEventType::UserFault,
        ];

        for (i, &et) in event_types.iter().enumerate() {
            log_one(&mut log, et, i as u32, b"test", (i as u64 + 1) * 100);
        }

        assert_eq!(
            log.len(),
            event_types.len(),
            "all event types must be logged"
        );

        // Verify chain integrity with all types.
        let result = log.verify_chain(&TEST_KEY);
        assert!(
            result.is_ok(),
            "chain must verify with all event types: {result:?}"
        );

        // Verify each entry has the correct event type.
        let (older, newer) = log.recent(event_types.len());
        let all_entries: alloc::vec::Vec<&AuditEntry> = older.iter().chain(newer.iter()).collect();
        for (i, &et) in event_types.iter().enumerate() {
            assert_eq!(
                all_entries[i].event_type, et,
                "entry {i} must have event type {et}"
            );
        }
    }

    // -- Error handling tests --

    #[test]
    fn no_key_rejected() {
        let mut log = AuditLog::new();
        let zero_key = [0u8; KEY_SIZE];
        let result = log.log_event(AuditEventType::AuthFail, 1, b"test", 100, &zero_key);
        assert_eq!(result, Err(AuditError::NoKey), "zero key must be rejected");
    }

    #[test]
    fn verify_empty_log() {
        let log = AuditLog::new();
        let result = log.verify_chain(&TEST_KEY);
        assert_eq!(
            result,
            Err(AuditError::Empty),
            "empty log must return Empty"
        );
    }

    #[test]
    fn verify_with_zero_key() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::AuthFail, 1, b"test", 100);

        let zero_key = [0u8; KEY_SIZE];
        let result = log.verify_chain(&zero_key);
        assert_eq!(
            result,
            Err(AuditError::NoKey),
            "zero key must be rejected on verify"
        );
    }

    #[test]
    fn wrong_key_fails_verify() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::AuthFail, 1, b"test", 100);
        log_one(&mut log, AuditEventType::CapDeny, 2, b"test2", 200);

        let wrong_key = [0xBB; KEY_SIZE];
        let result = log.verify_chain(&wrong_key);
        assert_eq!(
            result,
            Err(AuditError::ChainTampered),
            "wrong key must fail verification"
        );
    }

    // -- Recent entries tests --

    #[test]
    fn recent_returns_latest() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::AuthFail, 1, b"first", 100);
        log_one(&mut log, AuditEventType::CapDeny, 2, b"second", 200);
        log_one(&mut log, AuditEventType::PacketDeny, 3, b"third", 300);

        let (older, newer) = log.recent(2);
        let entries: alloc::vec::Vec<&AuditEntry> = older.iter().chain(newer.iter()).collect();
        assert_eq!(entries.len(), 2, "recent(2) must return 2 entries");
        assert_eq!(
            entries[0].timestamp, 200,
            "first of recent(2) must be second entry"
        );
        assert_eq!(
            entries[1].timestamp, 300,
            "second of recent(2) must be third entry"
        );
    }

    #[test]
    fn recent_more_than_count() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::AuthFail, 1, b"only", 100);

        let (older, newer) = log.recent(10);
        let total = older.len() + newer.len();
        assert_eq!(total, 1, "recent(10) with 1 entry must return 1");
    }

    #[test]
    fn recent_zero() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::AuthFail, 1, b"test", 100);

        let (older, newer) = log.recent(0);
        assert_eq!(
            older.len() + newer.len(),
            0,
            "recent(0) must return nothing"
        );
    }

    #[test]
    fn recent_after_wrap() {
        let mut log = AuditLog::new();
        for i in 0..(MAX_ENTRIES + 5) {
            log_one(
                &mut log,
                AuditEventType::PacketDeny,
                i as u32,
                b"wrap",
                i as u64 * 10,
            );
        }

        let (older, newer) = log.recent(3);
        let entries: alloc::vec::Vec<&AuditEntry> = older.iter().chain(newer.iter()).collect();
        assert_eq!(entries.len(), 3, "recent(3) after wrap must return 3");

        // Entries must be in chronological order.
        assert!(
            entries[0].timestamp < entries[1].timestamp,
            "recent entries must be in chronological order"
        );
        assert!(
            entries[1].timestamp < entries[2].timestamp,
            "recent entries must be in chronological order"
        );
    }

    // -- Detail truncation --

    #[test]
    fn detail_truncated_to_max() {
        let mut log = AuditLog::new();
        let long_detail = [b'X'; 128]; // Longer than DETAIL_LEN.
        log_one(&mut log, AuditEventType::AuthFail, 1, &long_detail, 100);

        let (older, newer) = log.recent(1);
        let entries: alloc::vec::Vec<&AuditEntry> = older.iter().chain(newer.iter()).collect();
        assert_eq!(
            entries[0].detail_len as usize, DETAIL_LEN,
            "detail must be truncated to DETAIL_LEN"
        );
        assert_eq!(
            entries[0].detail(),
            &[b'X'; DETAIL_LEN],
            "truncated detail must contain first DETAIL_LEN bytes"
        );
    }

    // -- Display / Debug --

    #[test]
    fn event_type_display() {
        assert_eq!(AuditEventType::AuthFail.to_string(), "AUTH_FAIL");
        assert_eq!(AuditEventType::PanicTrigger.to_string(), "PANIC_TRIGGER");
        assert_eq!(AuditEventType::DuressAttempt.to_string(), "DURESS_ATTEMPT");
    }

    #[test]
    fn entry_display() {
        let mut log = AuditLog::new();
        log_one(
            &mut log,
            AuditEventType::ModeChange,
            0,
            b"Daily->Sentinel",
            42000,
        );

        let (older, newer) = log.recent(1);
        let entries: alloc::vec::Vec<&AuditEntry> = older.iter().chain(newer.iter()).collect();
        let display = entries[0].to_string();
        assert!(display.contains("42000"), "display must contain timestamp");
        assert!(
            display.contains("MODE_CHANGE"),
            "display must contain event type"
        );
        assert!(
            display.contains("Daily->Sentinel"),
            "display must contain detail"
        );
    }

    #[test]
    fn entry_display_escapes_non_utf8_detail() {
        let mut log = AuditLog::new();
        // 0xFF is never a valid UTF-8 lead byte; the old
        // str::from_utf8(...).unwrap_or("?") path collapsed this whole
        // detail to a single '?', discarding the two legible bytes
        // alongside it.
        log_one(
            &mut log,
            AuditEventType::ModemAnomaly,
            7,
            &[0xFFu8, b'X', b'Y'],
            9000,
        );

        let (older, newer) = log.recent(1);
        let entries: alloc::vec::Vec<&AuditEntry> = older.iter().chain(newer.iter()).collect();
        let display = entries[0].to_string();
        assert!(
            display.contains("\\xff"),
            "non-UTF8 byte must render as a hex escape, not vanish: {display}"
        );
        assert!(
            display.contains("XY"),
            "legible bytes alongside a non-UTF8 byte must not be discarded: {display}"
        );
        assert!(
            !display.contains('?'),
            "detail must never collapse to a bare '?': {display}"
        );
    }

    #[test]
    fn audit_log_display() {
        let log = AuditLog::new();
        let display = alloc::format!("{log}");
        assert!(display.contains("0/"), "display must show count");
        assert!(
            display.contains("AuditLog"),
            "display must include type name"
        );
    }

    #[test]
    fn audit_error_display() {
        let no_key = AuditError::NoKey.to_string();
        assert!(no_key.contains("not available"), "NoKey display: {no_key}");

        let tampered = AuditError::ChainTampered.to_string();
        assert!(
            tampered.contains("tampering"),
            "ChainTampered display: {tampered}"
        );

        let empty = AuditError::Empty.to_string();
        assert!(empty.contains("empty"), "Empty display: {empty}");
    }

    // -- Single entry verification --

    #[test]
    fn single_entry_verifies() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::BootVerify, 0, b"kernel sig ok", 1);

        let result = log.verify_chain(&TEST_KEY);
        assert!(result.is_ok(), "single entry must verify: {result:?}");
    }

    // -- Chain after tamper at different positions --

    #[test]
    fn tamper_first_entry_detected() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::AuthFail, 1, b"a", 100);
        log_one(&mut log, AuditEventType::AuthFail, 1, b"b", 200);
        log_one(&mut log, AuditEventType::AuthFail, 1, b"c", 300);

        // Tamper with the first entry.
        log.entries[0].pid = 999;

        let result = log.verify_chain(&TEST_KEY);
        assert_eq!(
            result,
            Err(AuditError::ChainTampered),
            "first entry tamper must be detected"
        );
    }

    #[test]
    fn tamper_last_entry_detected() {
        let mut log = AuditLog::new();
        log_one(&mut log, AuditEventType::AuthFail, 1, b"a", 100);
        log_one(&mut log, AuditEventType::AuthFail, 1, b"b", 200);
        log_one(&mut log, AuditEventType::AuthFail, 1, b"c", 300);

        // Tamper with the last entry.
        log.entries[2].detail[0] = 0xFF;

        let result = log.verify_chain(&TEST_KEY);
        assert_eq!(
            result,
            Err(AuditError::ChainTampered),
            "last entry tamper must be detected"
        );
    }

    // -- MAX_ENTRIES sanity --

    #[test]
    fn max_entries_fits_in_64k() {
        let entry_size = core::mem::size_of::<AuditEntry>();
        let total = entry_size * MAX_ENTRIES;
        assert!(
            total <= BUFFER_SIZE,
            "entries must fit in 64 KiB: {MAX_ENTRIES} * {entry_size} = {total}"
        );
        // Verify we're not wasting too much space (at least 90% utilization).
        let utilization_pct = (total * 100) / BUFFER_SIZE;
        assert!(
            utilization_pct >= 80,
            "buffer utilization must be >= 80%: {utilization_pct}%"
        );
    }

    #[test]
    fn audit_log_struct_is_stack_safe() {
        // WHY: guards the #297 fix — AuditLog itself must stay small (a
        // Box<[AuditEntry]> fat pointer + a few scalars), never an inline
        // ~64 KiB array, so AuditLog::new() is safe to bind to a local on
        // the 64 KiB MT6739 boot stack.
        let size = core::mem::size_of::<AuditLog>();
        assert!(
            size < 256,
            "AuditLog must stay small (heap-backed entries); got {size} bytes"
        );
    }
}
