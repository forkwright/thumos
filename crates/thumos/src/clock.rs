//! Clock source selection over four independent axes.
//!
//! ## Why four axes and not one ordering
//!
//! A single precedence list answers "which source wins" by conflating
//! questions that have different answers. This module keeps them apart:
//!
//! - **Authentication** — can a reading be attributed to a party an attacker
//!   in the signal path cannot impersonate? Nothing here can, yet.
//! - **Freshness** — how long ago did the source last report?
//! - **Precision** — what granularity does *this implementation* extract,
//!   which is not the same as what the protocol can carry.
//! - **Agreement** — do the sources that are fresh tell the same story?
//!
//! Being first in an ordering is a statement about preference. It is not a
//! statement about any of the four, and the previous single list read as
//! though it were.
//!
//! ## Trust model
//!
//! | Source    | Authentication  | Precision | Why                                    |
//! |-----------|-----------------|-----------|----------------------------------------|
//! | GPS       | Unauthenticated | 1 s       | Civilian NMEA carries no signature, the M7's GPS firmware is proprietary, and the parser keeps whole seconds |
//! | NTP       | Unauthenticated | 1 s       | Plain NTP; NTS is not implemented, and this parser discards the 32-bit fraction the protocol does carry |
//! | Modem RTC | Unauthenticated | 1 s       | Carrier- and firmware-supplied          |
//! | Manual    | Unauthenticated | 1 s       | Operator-supplied on a device an adversary may be holding |
//!
//! Every row says `Unauthenticated`, and that uniformity is the finding rather
//! than a placeholder: no clock input this kernel accepts is authenticated
//! today. The axis exists so that adding NTS changes one value instead of
//! requiring the policy to be rewritten around it.
//!
//! ## Fail-closed policy
//!
//! Two rules apply before any reading is adopted, because a spoofed fix that
//! merely has to be *fresh* would otherwise move wall time at will and take
//! expiry checks, audit ordering and every time-dependent policy with it:
//!
//! - **A step no source may take alone.** A reading that disagrees with a
//!   fresh established clock by more than [`MAX_STEP_SECS`] is refused, and
//!   the clock is marked disputed. Checked only against a *fresh* established
//!   source: a first fix after a long power-off is a legitimate large step,
//!   and refusing it would leave the device with no clock at all.
//! - **Agreement between independent sources.** When two fresh sources differ
//!   by more than [`MAX_DISAGREEMENT_SECS`], neither is preferred over the
//!   other and the clock is marked disputed. One of them is lying and nothing
//!   here can say which.
//!
//! A disputed clock keeps serving the time it already had. It does not fall
//! back to zero -- a caller that asked for the time and got 1970 would be
//! worse off than one that got a slightly stale reading and can see the
//! dispute flag.
//!
//! ## NTP client
//!
//! Minimal UDP NTP exchange: sends a single `NTPv4` request to a configured
//! server, parses the response for server transmit timestamp, and computes
//! the clock offset. Uses the socket syscall layer (Wave 4) for UDP.

// WHY: the service loop owns ClockManager and seeds CLOCK_REALTIME from it;
// automatic GPS, NTP, and modem-time acquisition paths remain unused.
#![expect(
    dead_code,
    reason = "ClockManager is service-loop/syscall wired; automatic source acquisition remains unwired (#753)"
)]

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

/// Largest jump a single reading may make against a fresh established clock
/// before it is refused as implausible.
///
/// WHY 15 minutes: it is far wider than the drift any of these sources
/// accumulates between updates -- an uncorrected crystal is off by seconds a
/// day -- and far narrower than the shifts that make time-dependent policy
/// fail: certificate not-before/expiry windows, audit ordering, and the
/// hour-scale offsets a spoofed GPS fix would need to be useful.
const MAX_STEP_SECS: u64 = 15 * 60;

/// Largest difference between two fresh sources before neither is believed.
///
/// WHY tighter than [`MAX_STEP_SECS`]: a step is one source moving over time,
/// where some slack is ordinary. This is two independent sources describing
/// the same instant, where any real disagreement beyond transport delay means
/// one of them is wrong.
const MAX_DISAGREEMENT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Trust axes
// ---------------------------------------------------------------------------

/// Whether a reading can be attributed to a party an attacker in the signal
/// path cannot impersonate.
///
/// WHY this is separate from precedence (#861): "GPS is checked first" and
/// "GPS is trustworthy" are different claims, and collapsing them is what let
/// an unauthenticated satellite fix outrank everything else on the strength of
/// its provenance story. Satellite atomic clocks are accurate; the civilian
/// signal carrying their time to this device is unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceAuthentication {
    /// The reading could have been produced by anyone able to reach the
    /// device -- a spoofed transmitter, hostile modem firmware, or whoever
    /// is holding it.
    Unauthenticated,
    /// The reading is bound to a key this device trusts. Nothing produces
    /// this yet; NTS would be the first (#861).
    Authenticated,
}

// ---------------------------------------------------------------------------
// Clock source precedence
// ---------------------------------------------------------------------------

/// Where a wall-clock reading came from.
///
/// Variants are ordered by selection *preference*, highest first. Preference
/// is not trust: see [`Self::authentication`] for the axis that is, and the
/// module docs for why they are kept apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ClockSource {
    /// GPS-derived time — preferred when fresh, and unauthenticated.
    Gps,
    /// Plain-NTP-derived time — unauthenticated; NTS remains future work.
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

/// Manages the system wall clock using a source-precedence policy.
///
/// Selects the highest-precedence available source and tracks staleness. GPS,
/// NTP, and modem RTC are unauthenticated inputs; precedence is not trust (#861).
/// The monotonic kernel tick counter is used to determine when sources
/// become stale.
impl ClockSource {
    /// Whether a reading from this source is bound to a key this device
    /// trusts.
    ///
    /// Every arm answers `Unauthenticated` today. That is the finding, not an
    /// unfinished table: no clock input this kernel accepts carries a
    /// signature it can check. Adding NTS changes one arm.
    #[must_use]
    pub(crate) const fn authentication(self) -> SourceAuthentication {
        match self {
            // Civilian GPS is unsigned, and the M7's receiver firmware is
            // proprietary -- a fix is whatever the hardware says it is.
            Self::Gps
            // Plain NTP: the packet is validated for shape, not origin.
            | Self::Ntp
            // Supplied by the carrier through firmware the kernel contains
            // rather than trusts.
            | Self::ModemRtc
            // Typed on a device an adversary may be holding.
            | Self::Manual
            | Self::None => SourceAuthentication::Unauthenticated,
        }
    }

    /// The granularity this implementation extracts from the source, in
    /// seconds.
    ///
    /// WHY "this implementation" and not "this protocol": NTP carries a 32-bit
    /// fraction that the parser here discards, so the protocol's precision and
    /// the kernel's are different numbers. Recording the one that is true of
    /// the code keeps a future accuracy policy from being written against a
    /// precision nothing actually delivers.
    #[must_use]
    pub(crate) const fn precision_secs(self) -> u32 {
        match self {
            Self::Gps | Self::Ntp | Self::ModemRtc | Self::Manual => 1,
            Self::None => 0,
        }
    }
}

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
    /// Set when a reading was refused as an implausible step, or when two
    /// fresh sources disagreed. Cleared only when the sources agree again.
    disputed: bool,
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
            disputed: false,
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

    /// Whether the clock is currently in dispute: a reading was refused as an
    /// implausible step, or two fresh sources disagreed beyond
    /// [`MAX_DISAGREEMENT_SECS`].
    ///
    /// A disputed clock still serves the time it had. Callers that need to
    /// know whether time can be relied on -- expiry checks, audit ordering --
    /// read this rather than inferring trust from [`Self::current_source`].
    #[must_use]
    pub(crate) fn is_disputed(&self) -> bool {
        self.disputed
    }

    /// Whether `candidate` may replace the currently selected source.
    ///
    /// The rule that matters is the one that is vacuous today and must not be
    /// written later under pressure: an unauthenticated source may never
    /// displace an authenticated one. Every source is unauthenticated now, so
    /// this always permits -- but when NTS lands, GPS cannot silently take the
    /// clock back off it.
    fn authentication_permits(&self, candidate: ClockSource) -> bool {
        matches!(
            (
                self.current_source.authentication(),
                candidate.authentication()
            ),
            (SourceAuthentication::Unauthenticated, _)
                | (
                    SourceAuthentication::Authenticated,
                    SourceAuthentication::Authenticated
                )
        )
    }

    /// Whether `epoch` is a plausible reading given the clock already held.
    ///
    /// Returns true when there is nothing to compare against: no established
    /// source, or an established source that has gone stale. A first fix after
    /// a long power-off is a legitimate large step, and refusing it would
    /// leave the device with no clock rather than a wrong one.
    fn step_is_plausible(&self, epoch: u64, current_tick_ms: u64) -> bool {
        if self.current_source == ClockSource::None {
            return true;
        }
        if !self.gps_is_fresh(current_tick_ms) && !self.ntp_is_fresh(current_tick_ms) {
            return true;
        }
        let established = self.get_wall_clock(current_tick_ms);
        if established == 0 {
            return true;
        }
        established.abs_diff(epoch) <= MAX_STEP_SECS
    }

    /// Update from GPS time.
    ///
    /// GPS is preferred when fresh, and unauthenticated. The reading is
    /// refused when it would step the clock further than [`MAX_STEP_SECS`]
    /// against a fresh established source, or when the tick has gone backwards
    /// -- an out-of-order update would otherwise make a stale source look
    /// fresh, which is the cheapest way to promote a spoofed reading.
    ///
    /// Returns `true` if the update was accepted.
    pub(crate) fn update_from_gps(&mut self, time: GpsTime, current_tick_ms: u64) -> bool {
        if current_tick_ms < self.gps_update_tick {
            return false;
        }
        if !self.authentication_permits(ClockSource::Gps) {
            return false;
        }
        if !self.step_is_plausible(time.to_epoch_secs(), current_tick_ms) {
            self.disputed = true;
            return false;
        }

        self.gps_time = Some(time);
        self.gps_update_tick = current_tick_ms;
        self.current_source = ClockSource::Gps;
        self.last_update = current_tick_ms;
        self.check_agreement(current_tick_ms);
        true
    }

    /// Update from NTP offset.
    ///
    /// Plain NTP currently has second priority. It is accepted only if GPS is
    /// stale (> 60s since last update) or absent; neither source is authenticated
    /// by this implementation (#861).
    ///
    /// Returns `true` if the update was accepted.
    pub(crate) fn update_from_ntp(&mut self, offset: i64, current_tick_ms: u64) -> bool {
        if current_tick_ms < self.ntp_update_tick {
            return false;
        }
        if self.gps_is_fresh(current_tick_ms) {
            // GPS holds the clock, but a fresh NTP reading is still evidence:
            // record it so agreement can be checked, without letting it take
            // the selection.
            self.ntp_offset = Some(offset);
            self.ntp_update_tick = current_tick_ms;
            self.check_agreement(current_tick_ms);
            return false;
        }
        if !self.authentication_permits(ClockSource::Ntp) {
            return false;
        }
        let candidate = Self::ntp_epoch(offset, current_tick_ms);
        if !self.step_is_plausible(candidate, current_tick_ms) {
            self.disputed = true;
            return false;
        }

        self.ntp_offset = Some(offset);
        self.ntp_update_tick = current_tick_ms;
        self.current_source = ClockSource::Ntp;
        self.last_update = current_tick_ms;
        self.check_agreement(current_tick_ms);
        true
    }

    /// Update from modem RTC epoch.
    ///
    /// Modem RTC is the lowest-precedence automatic source. Only accepted if both
    /// GPS and NTP are stale.
    ///
    /// Returns `true` if the update was accepted.
    pub(crate) fn update_from_rtc(&mut self, epoch: u64, current_tick_ms: u64) -> bool {
        if current_tick_ms < self.rtc_update_tick {
            return false;
        }
        if self.gps_is_fresh(current_tick_ms) || self.ntp_is_fresh(current_tick_ms) {
            return false;
        }
        if !self.authentication_permits(ClockSource::ModemRtc) {
            return false;
        }
        if !self.step_is_plausible(epoch, current_tick_ms) {
            self.disputed = true;
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
    /// source order. A subsequent GPS or NTP update will override it, but neither
    /// input is authenticated; #861 owns the required policy and safeguards.
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
        // Agreement is re-checked here, not only on update: two sources can
        // fall out of agreement by one of them going stale, with no update to
        // trigger the check.
        self.check_agreement(current_tick_ms);
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
    /// Returns time from the first fresh source in the current provisional
    /// order: GPS > plain NTP > RTC > Manual. This is not an authentication
    /// ranking; #861 owns that correction.
    /// Returns 0 if no time source is available.
    #[must_use]
    pub(crate) fn get_wall_clock(&self, current_tick_ms: u64) -> u64 {
        // Try sources in provisional precedence order (#861).
        if let Some(ref gps_time) = self.gps_time
            && self.gps_is_fresh(current_tick_ms)
        {
            let base_epoch = gps_time.to_epoch_secs();
            let elapsed_secs = current_tick_ms.saturating_sub(self.gps_update_tick) / 1000;
            return base_epoch + elapsed_secs;
        }

        if let Some(offset) = self.ntp_offset
            && self.ntp_is_fresh(current_tick_ms)
        {
            return Self::ntp_epoch(offset, current_tick_ms);
        }

        if let Some(epoch) = self.rtc_epoch {
            let elapsed_secs = current_tick_ms.saturating_sub(self.rtc_update_tick) / 1000;
            return epoch + elapsed_secs;
        }

        if let Some(epoch) = self.manual_epoch {
            return epoch;
        }

        0
    }

    /// The wall clock an NTP offset implies at `current_tick_ms`.
    ///
    /// Factored out because both the accessor and the plausibility check need
    /// it, and two copies of a signed/unsigned conversion is two chances to
    /// get the sign wrong.
    fn ntp_epoch(offset: i64, current_tick_ms: u64) -> u64 {
        // INVARIANT: `monotonic_secs` is device uptime in seconds, and
        // `i64::MAX` seconds is ~292 billion years -- no uptime reaches that,
        // so this bit-reinterpretation cannot flip sign.
        let monotonic_secs = current_tick_ms / 1000;
        (monotonic_secs.cast_signed() + offset).cast_unsigned()
    }

    /// Mark the clock disputed when two fresh sources describe the same
    /// instant differently by more than [`MAX_DISAGREEMENT_SECS`].
    ///
    /// WHY this cannot pick a winner: the disagreement means one source is
    /// lying, and nothing available here distinguishes which. Preferring
    /// either would be choosing by precedence, which is exactly the reasoning
    /// #861 exists to remove. The clock keeps the time it has and says it is
    /// in dispute.
    fn check_agreement(&mut self, current_tick_ms: u64) {
        let (Some(gps), Some(offset)) = (self.gps_time.as_ref(), self.ntp_offset) else {
            return;
        };
        if !self.gps_is_fresh(current_tick_ms) || !self.ntp_is_fresh(current_tick_ms) {
            return;
        }
        let gps_epoch =
            gps.to_epoch_secs() + current_tick_ms.saturating_sub(self.gps_update_tick) / 1000;
        let ntp = Self::ntp_epoch(offset, current_tick_ms);
        self.disputed = gps_epoch.abs_diff(ntp) > MAX_DISAGREEMENT_SECS;
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

/// Build a minimal `NTPv4` client request packet (48 bytes).
///
/// Sets LI=0 (no warning), VN=4 (`NTPv4`), Mode=3 (client).
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
    let ntp_secs = u32::from_be_bytes([packet[40], packet[41], packet[42], packet[43]]) as u64;

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
/// offset = `server_time` - `local_send_time`
///
/// This is a simplified single-exchange offset. A production NTP client
/// would use the four-timestamp algorithm (T1, T2, T3, T4) with RTT
/// correction.
#[must_use]
pub(crate) fn calculate_ntp_offset(local_send_secs: u64, server_transmit_epoch: u64) -> i64 {
    // INVARIANT: unlike the other u64 -> i64 sites in this module, this
    // function has no wired-in NTP caller yet to bound `local_send_secs` by
    // construction, and `server_transmit_epoch` is meant to carry a value
    // parsed from a network-supplied NTP packet (see `parse_ntp_response`).
    // A bare `as i64` on either operand would silently flip sign for an
    // input >= 2^63, and subtracting two such reinterpreted values then
    // produces a small, plausible-looking but wrong offset instead of an
    // obviously-wrong one -- the same failure shape #670 closed on the GPS
    // side. Use checked widening with a stated saturation bound, and a
    // saturating subtract, so the result is well-defined for every `u64`
    // input this function could ever be called with, not just the ones a
    // not-yet-written caller happens to pass.
    let local = i64::try_from(local_send_secs).unwrap_or(i64::MAX);
    let server = i64::try_from(server_transmit_epoch).unwrap_or(i64::MAX);
    server.saturating_sub(local)
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

    /// The epoch `gps_time_2026()` describes.
    fn gps_epoch_2026() -> u64 {
        gps_time_2026().to_epoch_secs()
    }

    /// An NTP offset that puts the wall clock at the same instant
    /// `gps_time_2026()` describes, for a reading taken at `tick_ms`.
    ///
    /// WHY fixtures have to agree now: the disagreement and step policies
    /// refuse a source that contradicts an established one, so a test mixing a
    /// 1970 NTP offset with a 2026 GPS fix would be measuring the refusal
    /// rather than the precedence it meant to assert (#861).
    fn ntp_offset_agreeing_with_gps(tick_ms: u64) -> i64 {
        gps_epoch_2026().cast_signed() - (tick_ms / 1000).cast_signed()
    }

    #[test]
    fn no_clock_source_is_authenticated() {
        // #861: the axis exists so that "checked first" stops reading as
        // "trusted". Every source answering the same way is the finding, and
        // this pins it so that adding an authenticated source is a deliberate
        // edit here rather than a silent one.
        for source in [
            ClockSource::Gps,
            ClockSource::Ntp,
            ClockSource::ModemRtc,
            ClockSource::Manual,
            ClockSource::None,
        ] {
            assert_eq!(
                source.authentication(),
                SourceAuthentication::Unauthenticated,
                "{source:?} must not claim authentication this kernel cannot check"
            );
        }
    }

    #[test]
    fn precedence_is_not_authentication() {
        // GPS outranks modem RTC in the selector and is no better attested.
        // If these ever differ, it must be because a source gained a signature
        // rather than because it moved up the list.
        assert!(
            ClockSource::Gps < ClockSource::ModemRtc,
            "GPS must still be preferred over modem RTC"
        );
        assert_eq!(
            ClockSource::Gps.authentication(),
            ClockSource::ModemRtc.authentication(),
            "being preferred must not imply being better attested"
        );
    }

    #[test]
    fn a_spoofed_gps_jump_is_refused_and_disputes_the_clock() {
        // The attack #861 names: a forged fix moves wall time far enough to
        // defeat expiry and not-before checks. Against a fresh established
        // clock the reading must be refused outright, not merely deprioritised.
        let mut clock = ClockManager::new();
        assert!(clock.update_from_ntp(ntp_offset_agreeing_with_gps(0), 0));
        let before = clock.get_wall_clock(1_000);

        let mut forged = gps_time_2026();
        forged.hour = 20; // eight hours ahead
        assert!(
            !clock.update_from_gps(forged, 1_000),
            "a reading beyond MAX_STEP_SECS from a fresh clock must be refused"
        );
        assert!(
            clock.is_disputed(),
            "the refusal must mark the clock disputed"
        );
        assert_eq!(
            clock.get_wall_clock(1_000),
            before,
            "a refused reading must not move the clock it was refused against"
        );
        assert_eq!(
            clock.current_source(),
            ClockSource::Ntp,
            "a refused reading must not take the selection either"
        );
    }

    #[test]
    fn a_large_step_is_accepted_when_no_fresh_source_contradicts_it() {
        // The other half, and the reason the guard is conditional: a first fix
        // after a long power-off IS a large step, and refusing it would leave
        // the device with no clock rather than a wrong one.
        let mut clock = ClockManager::new();
        assert!(
            clock.update_from_gps(gps_time_2026(), 0),
            "the first reading has nothing to contradict and must be accepted"
        );

        // Let GPS go stale, then arrive somewhere far away.
        let mut later = gps_time_2026();
        later.year = 2027;
        assert!(
            clock.update_from_gps(later, 120_000),
            "a large step against a STALE clock must still be accepted"
        );
    }

    #[test]
    fn fresh_sources_that_disagree_dispute_the_clock() {
        // Neither source can be preferred: one of them is lying and nothing
        // here distinguishes which. Preferring either would be deciding by
        // precedence, which is the reasoning #861 removes.
        let mut clock = ClockManager::new();
        assert!(clock.update_from_gps(gps_time_2026(), 0));
        assert!(!clock.is_disputed(), "one source alone cannot disagree");

        // A fresh NTP reading two hours off, delivered while GPS still holds
        // the selection. It does not take the clock, but it is evidence.
        clock.update_from_ntp(ntp_offset_agreeing_with_gps(1_000) + 7_200, 1_000);
        assert!(
            clock.is_disputed(),
            "two fresh sources beyond MAX_DISAGREEMENT_SECS apart must dispute the clock"
        );
    }

    #[test]
    fn agreement_within_tolerance_does_not_dispute() {
        // The boundary matters in the other direction too: ordinary skew
        // between two honest sources must not read as an attack, or the flag
        // means nothing.
        let mut clock = ClockManager::new();
        assert!(clock.update_from_gps(gps_time_2026(), 0));
        clock.update_from_ntp(ntp_offset_agreeing_with_gps(1_000) + 5, 1_000);
        assert!(
            !clock.is_disputed(),
            "a five-second skew is not disagreement"
        );
    }

    #[test]
    fn a_dispute_clears_when_the_sources_agree_again() {
        // Source recovery: a disputed clock is a state, not a latch. A latch
        // would mean one bad reading permanently degrades the device.
        let mut clock = ClockManager::new();
        assert!(clock.update_from_gps(gps_time_2026(), 0));
        clock.update_from_ntp(ntp_offset_agreeing_with_gps(1_000) + 7_200, 1_000);
        assert!(clock.is_disputed());

        clock.update_from_ntp(ntp_offset_agreeing_with_gps(2_000), 2_000);
        assert!(
            !clock.is_disputed(),
            "sources agreeing again must clear the dispute"
        );
    }

    #[test]
    fn an_out_of_order_update_is_refused() {
        // A tick that has gone backwards would make a stale source look fresh,
        // which is the cheapest way to promote a reading the staleness policy
        // had already retired.
        let mut clock = ClockManager::new();
        assert!(clock.update_from_gps(gps_time_2026(), 10_000));
        assert!(
            !clock.update_from_gps(gps_time_2026(), 9_000),
            "a reading stamped before the last one must be refused"
        );
        assert!(
            !clock.update_from_ntp(ntp_offset_agreeing_with_gps(10_000), 9_000),
            "the same rule applies to every source"
        );
    }

    #[test]
    fn a_duplicate_update_at_the_same_tick_is_accepted() {
        // Duplicates are not out-of-order: a source re-reporting at the same
        // tick is reporting, and refusing it would make the rule above reject
        // ordinary repeated reads.
        let mut clock = ClockManager::new();
        assert!(clock.update_from_gps(gps_time_2026(), 10_000));
        assert!(
            clock.update_from_gps(gps_time_2026(), 10_000),
            "a repeated reading at the same tick must still be accepted"
        );
    }

    #[test]
    fn gps_overrides_ntp() {
        let mut clock = ClockManager::new();

        // Set NTP first.
        let accepted = clock.update_from_ntp(ntp_offset_agreeing_with_gps(0), 0);
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
        let accepted = clock.update_from_ntp(ntp_offset_agreeing_with_gps(1_000), 1_000);
        assert!(!accepted, "NTP must be rejected when GPS is fresh");
        assert_eq!(clock.current_source(), ClockSource::Gps);

        // NTP at tick 61_000 (GPS now stale, > 60s).
        let accepted = clock.update_from_ntp(ntp_offset_agreeing_with_gps(61_000), 61_000);
        assert!(accepted, "NTP must be accepted when GPS is stale");
        assert_eq!(clock.current_source(), ClockSource::Ntp);
    }

    #[test]
    fn rtc_accepted_when_both_stale() {
        let mut clock = ClockManager::new();

        // Set GPS at tick 0.
        clock.update_from_gps(gps_time_2026(), 0);

        // NTP at tick 61_000 — GPS is now stale (>60s), so NTP is accepted.
        let ntp_ok = clock.update_from_ntp(ntp_offset_agreeing_with_gps(61_000), 61_000);
        assert!(ntp_ok, "NTP must be accepted when GPS is stale");

        // RTC at tick 200_000 — GPS stale but NTP fresh (200_000 - 61_000 = 139s < 300s).
        let accepted = clock.update_from_rtc(gps_epoch_2026(), 200_000);
        assert!(!accepted, "RTC must be rejected when NTP is fresh");

        // RTC at tick 400_000 — both GPS and NTP stale (400_000 - 61_000 = 339s > 300s).
        let accepted = clock.update_from_rtc(gps_epoch_2026(), 400_000);
        assert!(
            accepted,
            "RTC must be accepted when both GPS and NTP are stale"
        );
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
        clock.set_manual(gps_epoch_2026(), 0);
        assert_eq!(
            clock.current_source(),
            ClockSource::Manual,
            "source must be Manual after set_manual with no other sources"
        );

        // RTC overrides manual (via evaluate).
        clock.update_from_rtc(gps_epoch_2026(), 1_000);
        assert_eq!(
            clock.current_source(),
            ClockSource::ModemRtc,
            "RTC must override Manual"
        );

        // NTP overrides RTC.
        clock.update_from_ntp(ntp_offset_agreeing_with_gps(2_000), 2_000);
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
        clock.ntp_offset = Some(ntp_offset_agreeing_with_gps(1_000));
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
            wall, 1_700_000_005,
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

    #[test]
    fn calculate_ntp_offset_saturates_instead_of_wrapping_sign() {
        // A `local_send_secs` >= 2^63 used to bit-flip to negative under a
        // bare `as i64`, so `server - local` computed as a small *positive*
        // number (0 - (-1) = 1) instead of reflecting that `local_send_secs`
        // is vastly larger than `server_transmit_epoch`. The saturating form
        // must report a large-magnitude NEGATIVE offset instead.
        let offset = calculate_ntp_offset(u64::MAX, 0);
        assert_eq!(
            offset,
            -(i64::MAX),
            "an out-of-range local time must saturate the offset negative, not wrap to +1"
        );

        // Symmetric case: an out-of-range server timestamp must saturate to
        // a large positive offset, not silently reinterpret as negative.
        let offset = calculate_ntp_offset(0, u64::MAX);
        assert_eq!(offset, i64::MAX);
    }
}
