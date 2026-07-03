//! Clock trust hierarchy: GPS > NTP > modem RTC.
//!
//! Provides wall-clock time to the kernel by selecting the most trustworthy
//! available source. GPS-derived time (atomic clocks on satellites) is always
//! preferred. NTP is accepted when GPS is stale. Modem RTC (carrier-provided,
//! potentially hostile) is the lowest-trust automatic source.
//!
//! ## Trust model
//!
//! | Source     | Trust   | Rationale                                          |
//! |------------|---------|---------------------------------------------------|
//! | GPS        | Highest | Atomic clocks on satellites, verified by fix       |
//! | NTP        | Medium  | Cryptographically authenticated (future NTS)       |
//! | Modem RTC  | Lowest  | Carrier-provided, potentially hostile               |
//! | Manual     | None    | User-set, no trust                                 |
//!
//! ## NTP client
//!
//! Minimal UDP NTP exchange: sends a single NTPv4 request to a configured
//! server, parses the response for server transmit timestamp, and computes
//! the clock offset. Uses the socket syscall layer (Wave 4) for UDP.

// WHY: clock module provides wall-clock policy, but kernel time and userspace
// syscalls still use the lower-level timer/time paths.
#![expect(dead_code, reason = "Clock trust manager is not wired into kernel time")]

extern crate alloc;

use crate::gps::GpsTime;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// GPS staleness threshold: 60 seconds. NTP is accepted when GPS time
/// is older than this.
const GPS_STALE_THRESHOLD_MS: u64 = 60_000;

/// NTP staleness threshold: 300 seconds. Modem RTC is accepted when both
/// GPS and NTP are older than this.
const NTP_STALE_THRESHOLD_MS: u64 = 300_000;

/// NTP packet size (48 bytes per RFC 5905).
const NTP_PACKET_SIZE: usize = 48;

/// NTP version 4, client mode (LI=0, VN=4, Mode=3).
const NTP_LI_VN_MODE: u8 = 0x23;

/// NTP server port.
const NTP_PORT: u16 = 123;

/// Number of seconds between 1900-01-01 (NTP epoch) and 1970-01-01 (Unix epoch).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

// ---------------------------------------------------------------------------
// Clock source hierarchy
// ---------------------------------------------------------------------------

/// Clock source with trust ranking.
///
/// Variants are ordered by trust level (highest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ClockSource {
    /// GPS-derived time — atomic clocks on satellites.
    Gps,
    /// NTP-derived time — cryptographically authenticated (future NTS).
    Ntp,
    /// Modem RTC — carrier-provided, potentially hostile.
    ModemRtc,
    /// User-set time — no trust.
    Manual,
    /// No time source available.
    None,
}

impl core::fmt::Display for ClockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Gps => write!(f, "GPS"),
            Self::Ntp => write!(f, "NTP"),
            Self::ModemRtc => write!(f, "modem RTC"),
            Self::Manual => write!(f, "manual"),
            Self::None => write!(f, "none"),
        }
    }
}

// ---------------------------------------------------------------------------
// Clock manager
// ---------------------------------------------------------------------------

/// Manages the system wall clock using a trust hierarchy of time sources.
///
/// Selects the most trustworthy available source and tracks staleness.
/// The monotonic kernel tick counter is used to determine when sources
/// become stale.
pub(crate) struct ClockManager {
    /// Current active time source.
    current_source: ClockSource,
    /// Kernel tick (ms) of the last time update.
    last_update: u64,
    /// Most recent GPS time (if available).
    gps_time: Option<GpsTime>,
    /// NTP offset in seconds from the monotonic clock.
    /// `wall_time = monotonic_secs + ntp_offset`
    ntp_offset: Option<i64>,
    /// Modem RTC epoch seconds (if provided by carrier).
    rtc_epoch: Option<u64>,
    /// Manual epoch seconds (if set by user).
    manual_epoch: Option<u64>,
    /// Kernel tick (ms) when GPS time was last updated.
    gps_update_tick: u64,
    /// Kernel tick (ms) when NTP time was last updated.
    ntp_update_tick: u64,
    /// Kernel tick (ms) when RTC time was last updated.
    rtc_update_tick: u64,
}

impl ClockManager {
    /// Create a new clock manager with no time sources.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            current_source: ClockSource::None,
            last_update: 0,
            gps_time: None,
            ntp_offset: None,
            rtc_epoch: None,
            manual_epoch: None,
            gps_update_tick: 0,
            ntp_update_tick: 0,
            rtc_update_tick: 0,
        }
    }

    /// Return the current active clock source.
    #[must_use]
    pub(crate) fn current_source(&self) -> ClockSource {
        self.current_source
    }

    /// Return the kernel tick (ms) of the last time update.
    #[must_use]
    pub(crate) fn last_update(&self) -> u64 {
        self.last_update
    }

    /// Update from GPS time.
    ///
    /// GPS is the highest-trust source. Always accepted regardless of
    /// other sources.
    pub(crate) fn update_from_gps(&mut self, time: GpsTime, current_tick_ms: u64) {
        self.gps_time = Some(time);
        self.gps_update_tick = current_tick_ms;
        self.current_source = ClockSource::Gps;
        self.last_update = current_tick_ms;
    }

    /// Update from NTP offset.
    ///
    /// NTP is medium-trust. Only accepted if GPS is stale (> 60s since
    /// last GPS update) or if no GPS time has ever been received.
    ///
    /// Returns `true` if the update was accepted.
    pub(crate) fn update_from_ntp(&mut self, offset: i64, current_tick_ms: u64) -> bool {
        if self.gps_is_fresh(current_tick_ms) {
            return false;
        }

        self.ntp_offset = Some(offset);
        self.ntp_update_tick = current_tick_ms;
        self.current_source = ClockSource::Ntp;
        self.last_update = current_tick_ms;
        true
    }

    /// Update from modem RTC epoch.
    ///
    /// Modem RTC is lowest-trust automatic source. Only accepted if both
    /// GPS and NTP are stale.
    ///
    /// Returns `true` if the update was accepted.
    pub(crate) fn update_from_rtc(&mut self, epoch: u64, current_tick_ms: u64) -> bool {
        if self.gps_is_fresh(current_tick_ms) || self.ntp_is_fresh(current_tick_ms) {
            return false;
        }

        self.rtc_epoch = Some(epoch);
        self.rtc_update_tick = current_tick_ms;
        self.current_source = ClockSource::ModemRtc;
        self.last_update = current_tick_ms;
        true
    }

    /// Set manual time (user-provided).
    ///
    /// Manual time is accepted unconditionally but ranked lowest in the
    /// trust hierarchy. A subsequent GPS or NTP update will override it.
    pub(crate) fn set_manual(&mut self, epoch: u64, current_tick_ms: u64) {
        self.manual_epoch = Some(epoch);
        // Only set source to Manual if nothing better is active.
        if self.current_source == ClockSource::None {
            self.current_source = ClockSource::Manual;
        }
        self.last_update = current_tick_ms;
    }

    /// Re-evaluate which source is current based on staleness.
    ///
    /// Should be called periodically. Demotes the current source if it
    /// has become stale, falling back to the next-best available source.
    pub(crate) fn evaluate(&mut self, current_tick_ms: u64) {
        if self.gps_is_fresh(current_tick_ms) {
            self.current_source = ClockSource::Gps;
        } else if self.ntp_is_fresh(current_tick_ms) {
            self.current_source = ClockSource::Ntp;
        } else if self.rtc_epoch.is_some() {
            self.current_source = ClockSource::ModemRtc;
        } else if self.manual_epoch.is_some() {
            self.current_source = ClockSource::Manual;
        } else {
            self.current_source = ClockSource::None;
        }
    }

    /// Get the best-known wall clock time as Unix epoch seconds.
    ///
    /// Returns the time from the highest-trust available source.
    /// Falls back through the hierarchy: GPS > NTP > RTC > Manual.
    /// Returns 0 if no time source is available.
    #[must_use]
    pub(crate) fn get_wall_clock(&self, current_tick_ms: u64) -> u64 {
        // Try sources in trust order.
        if let Some(ref gps_time) = self.gps_time && self.gps_is_fresh(current_tick_ms) {
            let base_epoch = gps_time.to_epoch_secs();
            let elapsed_secs =
                current_tick_ms.saturating_sub(self.gps_update_tick) / 1000;
            return base_epoch + elapsed_secs;
        }

        if let Some(offset) = self.ntp_offset && self.ntp_is_fresh(current_tick_ms) {
            // NTP offset is relative to monotonic clock.
            let monotonic_secs = current_tick_ms / 1000;
            return (monotonic_secs as i64 + offset) as u64;
        }

        if let Some(epoch) = self.rtc_epoch {
            let elapsed_secs =
                current_tick_ms.saturating_sub(self.rtc_update_tick) / 1000;
            return epoch + elapsed_secs;
        }

        if let Some(epoch) = self.manual_epoch {
            return epoch;
        }

        0
    }

    /// Check if GPS time is fresh (within staleness threshold).
    fn gps_is_fresh(&self, current_tick_ms: u64) -> bool {
        self.gps_time.is_some()
            && current_tick_ms.saturating_sub(self.gps_update_tick) < GPS_STALE_THRESHOLD_MS
    }

    /// Check if NTP time is fresh (within staleness threshold).
    fn ntp_is_fresh(&self, current_tick_ms: u64) -> bool {
        self.ntp_offset.is_some()
            && current_tick_ms.saturating_sub(self.ntp_update_tick) < NTP_STALE_THRESHOLD_MS
    }
}

// ---------------------------------------------------------------------------
// NTP client (minimal UDP exchange)
// ---------------------------------------------------------------------------

/// Build a minimal NTPv4 client request packet (48 bytes).
///
/// Sets LI=0 (no warning), VN=4 (NTPv4), Mode=3 (client).
/// All timestamp fields are zeroed; the server will fill in its transmit time.
#[must_use]
pub(crate) fn build_ntp_request() -> [u8; NTP_PACKET_SIZE] {
    let mut packet = [0u8; NTP_PACKET_SIZE];
    // Byte 0: LI=0, VN=4, Mode=3 → 0b00_100_011 = 0x23
    packet[0] = NTP_LI_VN_MODE;
    packet
}

/// Parse an NTP response and extract the server transmit timestamp.
///
/// The transmit timestamp is at bytes 40-47 of the NTP packet:
/// - Bytes 40-43: seconds since NTP epoch (1900-01-01)
/// - Bytes 44-47: fractional seconds
///
/// Validates packet structure before trusting the timestamp (#367): mode
/// must be 4 (server response), the Leap Indicator must not be 3
/// (unsynchronized), and stratum must be in `1..16` (0 = kiss-o'-death,
/// 16 = unsynchronized). This is structural validation only -- NTP
/// authentication (NTS) is future work per the module doc.
///
/// Returns the transmit timestamp as Unix epoch seconds, or `None` if the
/// packet is too short, structurally invalid, or the timestamp is zero.
#[must_use]
pub(crate) fn parse_ntp_response(packet: &[u8]) -> Option<u64> {
    if packet.len() < NTP_PACKET_SIZE {
        return None;
    }

    // Mode (bits [2:0] of byte 0) must be 4 (server response). Rejects
    // client/broadcast/reserved-mode packets an adversary could replay (#367).
    if packet[0] & 0x07 != 4 {
        return None;
    }

    // Leap Indicator (bits [7:6] of byte 0) of 3 signals the server clock is
    // unsynchronized ("alarm condition" per RFC 5905 SS7.3) and must be
    // discarded rather than trusted (#367).
    if packet[0] >> 6 == 3 {
        return None;
    }

    // Stratum (byte 1): 0 is kiss-o'-death (server refusing service, no
    // valid time attached), 16 is unsynchronized. Valid strata are 1-15;
    // both boundary conditions must be rejected (#367).
    let stratum = packet[1];
    if stratum == 0 || stratum >= 16 {
        return None;
    }

    // Transmit timestamp: seconds at bytes 40-43 (big-endian).
    let ntp_secs = u32::from_be_bytes([
        packet[40],
        packet[41],
        packet[42],
        packet[43],
    ]) as u64;

    if ntp_secs == 0 {
        return None;
    }

    // Convert NTP epoch (1900) to Unix epoch (1970).
    Some(ntp_secs.saturating_sub(NTP_UNIX_OFFSET))
}

/// Calculate the NTP clock offset from a request/response exchange.
///
/// Given the local monotonic time (in seconds) when the request was sent
/// and the server's transmit timestamp (Unix epoch seconds), computes the
/// offset to add to the local monotonic clock to get wall time.
///
/// offset = server_time - local_send_time
///
/// This is a simplified single-exchange offset. A production NTP client
/// would use the four-timestamp algorithm (T1, T2, T3, T4) with RTT
/// correction.
#[must_use]
pub(crate) fn calculate_ntp_offset(
    local_send_secs: u64,
    server_transmit_epoch: u64,
) -> i64 {
    server_transmit_epoch as i64 - local_send_secs as i64
}

/// NTP server endpoint for the clock manager.
#[derive(Debug, Clone, Copy)]
pub struct NtpServer {
    /// Server IPv4 address bytes.
    pub ip: [u8; 4],
    /// Server port (typically 123).
    pub port: u16,
}

impl NtpServer {
    /// Create an NTP server endpoint.
    #[must_use]
    pub(crate) const fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port }
    }
}

/// Default NTP server: pool.ntp.org primary (time.google.com: 216.239.35.0).
pub(crate) const DEFAULT_NTP_SERVER: NtpServer = NtpServer::new([216, 239, 35, 0], NTP_PORT);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn gps_time_2026() -> GpsTime {
        GpsTime {
            year: 2026,
            month: 4,
            day: 9,
            hour: 12,
            minute: 0,
            second: 0,
        }
    }

    #[test]
    fn gps_overrides_ntp() {
        let mut clock = ClockManager::new();

        // Set NTP first.
        let accepted = clock.update_from_ntp(1_000_000, 0);
        assert!(accepted, "NTP must be accepted when no GPS");
        assert_eq!(clock.current_source(), ClockSource::Ntp);

        // GPS update should override.
        clock.update_from_gps(gps_time_2026(), 100);
        assert_eq!(
            clock.current_source(),
            ClockSource::Gps,
            "GPS must override NTP"
        );
    }

    #[test]
    fn ntp_accepted_when_gps_stale() {
        let mut clock = ClockManager::new();

        // Set GPS at tick 0.
        clock.update_from_gps(gps_time_2026(), 0);
        assert_eq!(clock.current_source(), ClockSource::Gps);

        // NTP at tick 1000 (GPS still fresh, within 60s).
        let accepted = clock.update_from_ntp(1_000_000, 1_000);
        assert!(!accepted, "NTP must be rejected when GPS is fresh");
        assert_eq!(clock.current_source(), ClockSource::Gps);

        // NTP at tick 61_000 (GPS now stale, > 60s).
        let accepted = clock.update_from_ntp(1_000_000, 61_000);
        assert!(accepted, "NTP must be accepted when GPS is stale");
        assert_eq!(clock.current_source(), ClockSource::Ntp);
    }

    #[test]
    fn rtc_accepted_when_both_stale() {
        let mut clock = ClockManager::new();

        // Set GPS at tick 0.
        clock.update_from_gps(gps_time_2026(), 0);

        // NTP at tick 61_000 — GPS is now stale (>60s), so NTP is accepted.
        let ntp_ok = clock.update_from_ntp(1_000_000, 61_000);
        assert!(ntp_ok, "NTP must be accepted when GPS is stale");

        // RTC at tick 200_000 — GPS stale but NTP fresh (200_000 - 61_000 = 139s < 300s).
        let accepted = clock.update_from_rtc(1_700_000_000, 200_000);
        assert!(!accepted, "RTC must be rejected when NTP is fresh");

        // RTC at tick 400_000 — both GPS and NTP stale (400_000 - 61_000 = 339s > 300s).
        let accepted = clock.update_from_rtc(1_700_000_000, 400_000);
        assert!(accepted, "RTC must be accepted when both GPS and NTP are stale");
        assert_eq!(clock.current_source(), ClockSource::ModemRtc);
    }

    #[test]
    fn current_source_reflects_priority() {
        let mut clock = ClockManager::new();
        assert_eq!(
            clock.current_source(),
            ClockSource::None,
            "initial source must be None"
        );

        // Manual set.
        clock.set_manual(1_700_000_000, 0);
        assert_eq!(
            clock.current_source(),
            ClockSource::Manual,
            "source must be Manual after set_manual with no other sources"
        );

        // RTC overrides manual (via evaluate).
        clock.update_from_rtc(1_700_000_000, 1_000);
        assert_eq!(
            clock.current_source(),
            ClockSource::ModemRtc,
            "RTC must override Manual"
        );

        // NTP overrides RTC.
        clock.update_from_ntp(1_000_000, 2_000);
        assert_eq!(
            clock.current_source(),
            ClockSource::Ntp,
            "NTP must override RTC"
        );

        // GPS overrides NTP.
        clock.update_from_gps(gps_time_2026(), 3_000);
        assert_eq!(
            clock.current_source(),
            ClockSource::Gps,
            "GPS must override NTP"
        );
    }

    #[test]
    fn evaluate_demotes_stale_sources() {
        let mut clock = ClockManager::new();

        // Set GPS at tick 0.
        clock.update_from_gps(gps_time_2026(), 0);
        assert_eq!(clock.current_source(), ClockSource::Gps);

        // Set NTP at tick 1000.
        // GPS is still fresh, so NTP is rejected via update_from_ntp.
        // Set it directly to simulate a past NTP update.
        clock.ntp_offset = Some(1_000_000);
        clock.ntp_update_tick = 1_000;

        // Evaluate at tick 70_000 — GPS stale, NTP fresh.
        clock.evaluate(70_000);
        assert_eq!(
            clock.current_source(),
            ClockSource::Ntp,
            "evaluate must demote GPS to NTP when GPS is stale"
        );

        // Evaluate at tick 400_000 — both stale, no RTC.
        clock.evaluate(400_000);
        assert_eq!(
            clock.current_source(),
            ClockSource::None,
            "evaluate must demote to None when all sources are stale"
        );
    }

    #[test]
    fn get_wall_clock_uses_best_source() {
        let mut clock = ClockManager::new();

        // No source.
        assert_eq!(clock.get_wall_clock(0), 0, "no source must return 0");

        // GPS.
        let time = gps_time_2026();
        let expected_epoch = time.to_epoch_secs();
        clock.update_from_gps(time, 0);
        let wall = clock.get_wall_clock(5_000); // 5 seconds later
        assert_eq!(
            wall,
            expected_epoch + 5,
            "wall clock must advance with monotonic clock"
        );
    }

    #[test]
    fn get_wall_clock_ntp_positive_offset_path() {
        // #376: the NTP code path (as opposed to GPS) was previously
        // untested by get_wall_clock -- this exercises it directly.
        let mut clock = ClockManager::new();
        let accepted = clock.update_from_ntp(1_700_000_000, 0);
        assert!(accepted, "NTP must be accepted when no GPS is present");

        let wall = clock.get_wall_clock(5_000); // 5 seconds later
        assert_eq!(
            wall,
            1_700_000_005,
            "wall clock must be monotonic_secs + ntp offset"
        );
    }

    #[test]
    fn get_wall_clock_ntp_large_negative_offset_wraps_to_huge_timestamp() {
        // #376: documents the current (unguarded) behavior of the NTP
        // path. A hostile NTP server supplying a large-negative offset
        // drives get_wall_clock() to silently wrap to a near-u64::MAX
        // timestamp via the `as u64` cast rather than erroring or
        // clamping. This is the exact silent-wraparound surface #376
        // exists to make visible, as a regression guard: a future
        // plausibility guard (companion to #367's packet validation)
        // should make this test's expected value change to a bounded
        // result, at which point this assertion should be updated
        // deliberately rather than silently.
        let mut clock = ClockManager::new();
        clock.ntp_offset = Some(i64::MIN);
        clock.ntp_update_tick = 0;

        let wall = clock.get_wall_clock(0);
        assert_eq!(
            wall,
            i64::MIN as u64,
            "unguarded NTP path must wrap exactly as documented (#376)"
        );
    }

    // -- NTP packet tests --

    #[test]
    fn build_ntp_request_has_correct_header() {
        let packet = build_ntp_request();
        assert_eq!(packet.len(), 48, "NTP packet must be 48 bytes");
        assert_eq!(
            packet[0], 0x23,
            "first byte must be LI=0, VN=4, Mode=3 (0x23)"
        );
        // Rest should be zeros.
        assert!(
            packet[1..].iter().all(|&b| b == 0),
            "all bytes after header must be zero"
        );
    }

    #[test]
    fn parse_ntp_response_extracts_timestamp() {
        let mut packet = [0u8; 48];
        // LI=0, VN=4, Mode=4 (server response) -- required for the packet to
        // pass the structural validation added for #367.
        packet[0] = 0x24;
        packet[1] = 1; // stratum 1 (primary reference) -- valid, non-zero, <16.
        // Set transmit timestamp at bytes 40-43.
        // NTP epoch value = Unix epoch + NTP_UNIX_OFFSET
        let unix_time: u64 = 1_700_000_000;
        let ntp_time = (unix_time + NTP_UNIX_OFFSET) as u32;
        packet[40..44].copy_from_slice(&ntp_time.to_be_bytes());

        let result = parse_ntp_response(&packet);
        assert_eq!(
            result,
            Some(unix_time),
            "must extract Unix epoch from NTP timestamp"
        );
    }

    #[test]
    fn parse_ntp_response_rejects_wrong_mode() {
        // #367: mode bits [2:0] of byte 0 must be 4 (server response).
        let mut packet = [0u8; 48];
        packet[0] = 0x03; // LI=0, VN=0, Mode=3 (client, not server)
        packet[1] = 1;
        let unix_time: u64 = 1_700_000_000;
        let ntp_time = (unix_time + NTP_UNIX_OFFSET) as u32;
        packet[40..44].copy_from_slice(&ntp_time.to_be_bytes());
        assert_eq!(
            parse_ntp_response(&packet),
            None,
            "non-server mode must be rejected"
        );
    }

    #[test]
    fn parse_ntp_response_rejects_alarm_leap_indicator() {
        // #367: LI = 3 (bits [7:6] of byte 0) signals an unsynchronized
        // server clock and must be discarded.
        let mut packet = [0u8; 48];
        packet[0] = 0xE4; // LI=3, VN=4, Mode=4
        packet[1] = 1;
        let unix_time: u64 = 1_700_000_000;
        let ntp_time = (unix_time + NTP_UNIX_OFFSET) as u32;
        packet[40..44].copy_from_slice(&ntp_time.to_be_bytes());
        assert_eq!(
            parse_ntp_response(&packet),
            None,
            "LI=3 (alarm/unsynchronized) must be rejected"
        );
    }

    #[test]
    fn parse_ntp_response_rejects_kiss_of_death_stratum() {
        // #367: stratum 0 is kiss-o'-death -- the server is refusing
        // service and the packet carries no valid time.
        let mut packet = [0u8; 48];
        packet[0] = 0x24; // LI=0, VN=4, Mode=4
        packet[1] = 0; // stratum 0
        let unix_time: u64 = 1_700_000_000;
        let ntp_time = (unix_time + NTP_UNIX_OFFSET) as u32;
        packet[40..44].copy_from_slice(&ntp_time.to_be_bytes());
        assert_eq!(
            parse_ntp_response(&packet),
            None,
            "stratum 0 (kiss-o'-death) must be rejected"
        );
    }

    #[test]
    fn parse_ntp_response_rejects_unsynchronized_stratum() {
        // #367: stratum 16 means the server itself is unsynchronized.
        let mut packet = [0u8; 48];
        packet[0] = 0x24; // LI=0, VN=4, Mode=4
        packet[1] = 16; // stratum 16
        let unix_time: u64 = 1_700_000_000;
        let ntp_time = (unix_time + NTP_UNIX_OFFSET) as u32;
        packet[40..44].copy_from_slice(&ntp_time.to_be_bytes());
        assert_eq!(
            parse_ntp_response(&packet),
            None,
            "stratum 16 (unsynchronized) must be rejected"
        );
    }

    #[test]
    fn parse_ntp_response_rejects_short_packet() {
        let packet = [0u8; 20];
        assert_eq!(
            parse_ntp_response(&packet),
            None,
            "short packet must return None"
        );
    }

    #[test]
    fn parse_ntp_response_rejects_zero_timestamp() {
        let packet = [0u8; 48];
        assert_eq!(
            parse_ntp_response(&packet),
            None,
            "zero timestamp must return None"
        );
    }

    #[test]
    fn calculate_ntp_offset_computes_correctly() {
        let offset = calculate_ntp_offset(1000, 1_700_000_000);
        assert_eq!(
            offset,
            1_700_000_000 - 1000,
            "offset must be server_time - local_time"
        );
    }
}
