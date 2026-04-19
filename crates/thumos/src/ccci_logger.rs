//! CCCI traffic logger, modem baseline profiler, anomaly detection,
//! and channel firewall.
//!
//! Phase 10 Waves 2+3: provides traffic visibility and containment for
//! the AP-modem CCCI link.
//!
//! ## Architecture
//!
//! 1. **[`CcciLogger`]** -- 4 KB ring buffer of packet headers (no payload).
//!    Sits inside the receive path; every validated packet header is recorded.
//!
//! 2. **[`ModemBaseline`]** -- 60-second post-boot traffic profile.  Per-channel
//!    min/max packet rates and sizes, active/inactive flags.  Built from the
//!    logger's history.
//!
//! 3. **Anomaly detection** -- live traffic compared against baseline.  Flags
//!    unexpected active channels, rate spikes > 3x, out-of-range data0 values.
//!    Emits [`CcciAnomaly`] events for the audit log.
//!
//! 4. **[`CcciFirewall`]** -- channel allowlist with default-deny policy.
//!    Mode-dependent allowlists (Daily / Sentinel / Panic).  Dropped packets
//!    are audit-logged.
//!
//! ## Security
//!
//! All structures are fixed-size, no_std, no heap allocation.  The firewall
//! evaluates *before* packet dispatch -- non-allowlisted channels never reach
//! higher layers.

use core::fmt;

use crate::ccci::CcciChannel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Logger ring buffer capacity in entries.
///
/// 4 KB budget / size_of::<CcciLogEntry>() -- each entry is 28 bytes,
/// giving 146 entries.  We round down to 128 (power of 2) for efficient
/// modular arithmetic.
const LOG_CAPACITY: usize = 128;

/// Number of CCCI channels (0..=21, 22 total).
const CHANNEL_COUNT: usize = 22;

/// Baseline observation window in milliseconds (60 seconds).
const BASELINE_WINDOW_MS: u64 = 60_000;

/// Anomaly rate spike threshold: flag if live rate exceeds 3x baseline max.
const RATE_SPIKE_FACTOR: u32 = 3;

/// Maximum channels in the firewall allowlist.
const MAX_ALLOWLIST: usize = 16;

// ---------------------------------------------------------------------------
// PacketDirection
// ---------------------------------------------------------------------------

/// Direction of a CCCI packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum PacketDirection {
    /// AP to modem (TX / uplink).
    Tx,
    /// Modem to AP (RX / downlink).
    Rx,
}

impl fmt::Display for PacketDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tx => write!(f, "TX"),
            Self::Rx => write!(f, "RX"),
        }
    }
}

// ---------------------------------------------------------------------------
// CcciLogEntry
// ---------------------------------------------------------------------------

/// A single CCCI packet header log entry (no payload).
///
/// Records the header fields needed for traffic analysis without storing
/// potentially large payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct CcciLogEntry {
    /// Monotonic timestamp (kernel ticks, milliseconds).
    pub timestamp: u64,
    /// CCCI channel number.
    pub channel: u32,
    /// Packet direction.
    pub direction: PacketDirection,
    /// Header data0 field (length for data packets, CCCI_MAGIC for control).
    pub data0: u32,
    /// Header data1 field (offset/index on some channels).
    pub data1: u32,
    /// Total packet length in bytes (header + payload).
    pub packet_len: u16,
}

impl fmt::Display for CcciLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[t={} ch={} {} d0={:#x} d1={:#x} len={}]",
            self.timestamp,
            self.channel,
            self.direction,
            self.data0,
            self.data1,
            self.packet_len,
        )
    }
}

// ---------------------------------------------------------------------------
// CcciLogger
// ---------------------------------------------------------------------------

/// Fixed-size ring buffer recording CCCI packet headers.
///
/// Capacity: [`LOG_CAPACITY`] entries (fits within 4 KB).  Oldest entries
/// are silently overwritten when full.
#[must_use]
pub(crate) struct CcciLogger {
    /// Ring buffer storage.
    entries: [CcciLogEntry; LOG_CAPACITY],
    /// Next write index.
    head: usize,
    /// Number of live entries (0..=LOG_CAPACITY).
    count: usize,
}

impl CcciLogger {
    /// Create a new, empty logger.
    pub(crate) const fn new() -> Self {
        const EMPTY: CcciLogEntry = CcciLogEntry {
            timestamp: 0,
            channel: 0,
            direction: PacketDirection::Rx,
            data0: 0,
            data1: 0,
            packet_len: 0,
        };
        Self {
            entries: [EMPTY; LOG_CAPACITY],
            head: 0,
            count: 0,
        }
    }

    /// Record a packet header.
    pub(crate) fn record(&mut self, entry: CcciLogEntry) {
        self.entries[self.head] = entry;
        self.head = (self.head + 1) % LOG_CAPACITY;
        if self.count < LOG_CAPACITY {
            self.count += 1;
        }
    }

    /// Number of live entries.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.count
    }

    /// Whether the logger is empty.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over all live entries in chronological order (oldest first).
    ///
    /// Returns a pair of slices `(older, newer)` due to the ring buffer
    /// potentially wrapping.
    #[must_use]
    pub(crate) fn entries(&self) -> (&[CcciLogEntry], &[CcciLogEntry]) {
        if self.count == 0 {
            return (&[], &[]);
        }
        if self.count < LOG_CAPACITY {
            // Not wrapped: entries are [0..count).
            (&self.entries[..self.count], &[])
        } else {
            // Wrapped: oldest starts at head, newest ends at head-1.
            (&self.entries[self.head..], &self.entries[..self.head])
        }
    }

    /// Get an entry by chronological index (0 = oldest live entry).
    #[must_use]
    pub(crate) fn get(&self, index: usize) -> Option<&CcciLogEntry> {
        if index >= self.count {
            return None;
        }
        let actual = if self.count < LOG_CAPACITY {
            index
        } else {
            (self.head + index) % LOG_CAPACITY
        };
        Some(&self.entries[actual])
    }

    /// Count packets on a given channel within a time window.
    ///
    /// Scans live entries where `timestamp >= since`.
    #[must_use]
    pub(crate) fn channel_count_since(&self, channel: u32, since: u64) -> u32 {
        let mut count = 0u32;
        let (older, newer) = self.entries();
        for entry in older.iter().chain(newer.iter()) {
            if entry.timestamp >= since && entry.channel == channel {
                count = count.saturating_add(1);
            }
        }
        count
    }
}

impl Default for CcciLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CcciLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CcciLogger")
            .field("count", &self.count)
            .field("capacity", &LOG_CAPACITY)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for CcciLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CcciLogger({}/{})", self.count, LOG_CAPACITY)
    }
}

// ---------------------------------------------------------------------------
// ChannelStats
// ---------------------------------------------------------------------------

/// Per-channel traffic statistics for baseline profiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct ChannelStats {
    /// Minimum packet rate observed (packets per observation window).
    pub min_rate: u32,
    /// Maximum packet rate observed.
    pub max_rate: u32,
    /// Minimum packet size (bytes).
    pub min_size: u16,
    /// Maximum packet size (bytes).
    pub max_size: u16,
    /// Minimum data0 value observed.
    pub min_data0: u32,
    /// Maximum data0 value observed.
    pub max_data0: u32,
    /// Whether this channel was active during the baseline window.
    pub active: bool,
}

impl ChannelStats {
    /// Create empty stats for an inactive channel.
    const fn inactive() -> Self {
        Self {
            min_rate: 0,
            max_rate: 0,
            min_size: 0,
            max_size: 0,
            min_data0: 0,
            max_data0: 0,
            active: false,
        }
    }
}

impl fmt::Display for ChannelStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.active {
            write!(
                f,
                "rate=[{},{}] size=[{},{}] d0=[{:#x},{:#x}]",
                self.min_rate,
                self.max_rate,
                self.min_size,
                self.max_size,
                self.min_data0,
                self.max_data0,
            )
        } else {
            write!(f, "inactive")
        }
    }
}

// ---------------------------------------------------------------------------
// ModemBaseline
// ---------------------------------------------------------------------------

/// Modem traffic baseline built from the first 60 seconds of post-boot
/// traffic.
///
/// Per-channel statistics provide the reference for anomaly detection.
#[derive(Debug, Clone)]
#[must_use]
pub struct ModemBaseline {
    /// Per-channel statistics (indexed by channel number 0..CHANNEL_COUNT).
    pub channels: [ChannelStats; CHANNEL_COUNT],
    /// Start timestamp of the baseline window.
    pub window_start: u64,
    /// End timestamp of the baseline window.
    pub window_end: u64,
}

impl ModemBaseline {
    /// Create an empty baseline with no active channels.
    pub(crate) const fn empty() -> Self {
        Self {
            channels: [ChannelStats::inactive(); CHANNEL_COUNT],
            window_start: 0,
            window_end: 0,
        }
    }
}

impl fmt::Display for ModemBaseline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active_count = self.channels.iter().filter(|c| c.active).count();
        write!(
            f,
            "ModemBaseline({} active channels, window=[{},{}])",
            active_count, self.window_start, self.window_end,
        )
    }
}

/// Build a modem traffic baseline from the logger's recorded entries.
///
/// Scans all entries in the logger that fall within a 60-second window
/// ending at `window_end_ms`.  For each channel, computes packet count
/// (used as rate), min/max packet size, and min/max data0 values.
///
/// # Arguments
///
/// * `log` -- the CCCI traffic logger with recorded entries
/// * `window_end_ms` -- the end timestamp of the 60s baseline window
#[must_use]
pub(crate) fn build_baseline(log: &CcciLogger, window_end_ms: u64) -> ModemBaseline {
    let window_start = window_end_ms.saturating_sub(BASELINE_WINDOW_MS);

    let mut baseline = ModemBaseline {
        channels: [ChannelStats::inactive(); CHANNEL_COUNT],
        window_start,
        window_end: window_end_ms,
    };

    // Per-channel accumulators.
    let mut packet_counts = [0u32; CHANNEL_COUNT];

    let (older, newer) = log.entries();
    for entry in older.iter().chain(newer.iter()) {
        if entry.timestamp < window_start || entry.timestamp > window_end_ms {
            continue;
        }
        let ch = entry.channel as usize;
        if ch >= CHANNEL_COUNT {
            continue;
        }

        let stats = &mut baseline.channels[ch];
        let count = &mut packet_counts[ch];

        if !stats.active {
            // First packet on this channel: initialize min/max.
            stats.active = true;
            stats.min_size = entry.packet_len;
            stats.max_size = entry.packet_len;
            stats.min_data0 = entry.data0;
            stats.max_data0 = entry.data0;
        } else {
            if entry.packet_len < stats.min_size {
                stats.min_size = entry.packet_len;
            }
            if entry.packet_len > stats.max_size {
                stats.max_size = entry.packet_len;
            }
            if entry.data0 < stats.min_data0 {
                stats.min_data0 = entry.data0;
            }
            if entry.data0 > stats.max_data0 {
                stats.max_data0 = entry.data0;
            }
        }

        *count = count.saturating_add(1);
    }

    // Copy packet counts into rate fields.
    // WHY: during baseline, rate = total count over the window. We store
    // the same value for min and max since this is a single observation.
    // Subsequent baselines could merge, but for the initial post-boot
    // capture a single observation is sufficient.
    for (ch, &count) in packet_counts.iter().enumerate() {
        if baseline.channels[ch].active {
            baseline.channels[ch].min_rate = count;
            baseline.channels[ch].max_rate = count;
        }
    }

    baseline
}

// ---------------------------------------------------------------------------
// CcciAnomaly
// ---------------------------------------------------------------------------

/// Type of CCCI traffic anomaly detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum AnomalyKind {
    /// A channel that was inactive during baseline is now active.
    UnexpectedChannel,
    /// Packet rate on a channel exceeds 3x the baseline maximum.
    RateSpike,
    /// data0 value is outside the range observed during baseline.
    Data0OutOfRange,
}

impl fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedChannel => write!(f, "unexpected channel active"),
            Self::RateSpike => write!(f, "packet rate spike >3x baseline"),
            Self::Data0OutOfRange => write!(f, "data0 outside baseline range"),
        }
    }
}

/// A CCCI traffic anomaly event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct CcciAnomaly {
    /// Timestamp of the anomaly detection.
    pub timestamp: u64,
    /// CCCI channel number.
    pub channel: u32,
    /// Type of anomaly.
    pub kind: AnomalyKind,
    /// Observed value (rate count, or data0 value).
    pub observed: u32,
    /// Baseline maximum (for rate spikes) or baseline range bound.
    pub baseline_max: u32,
}

impl fmt::Display for CcciAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CcciAnomaly(ch={} {} observed={} baseline_max={})",
            self.channel, self.kind, self.observed, self.baseline_max,
        )
    }
}

/// Maximum number of anomalies returned from a single detection pass.
const MAX_ANOMALIES: usize = 16;

/// Compare live traffic against a baseline and return detected anomalies.
///
/// Checks performed per channel:
/// 1. Unexpected channel active (was inactive during baseline).
/// 2. Rate spike: packet count in the last `window_ms` exceeds
///    3x the baseline maximum rate.
/// 3. data0 out of range: most recent packet's data0 falls outside
///    the baseline `[min_data0, max_data0]` range.
///
/// # Arguments
///
/// * `log` -- current traffic logger
/// * `baseline` -- the reference baseline
/// * `now` -- current timestamp in milliseconds
/// * `window_ms` -- the time window to measure current rates over
///
/// Returns an array of up to [`MAX_ANOMALIES`] anomalies and the count.
#[must_use]
pub(crate) fn detect_anomalies(
    log: &CcciLogger,
    baseline: &ModemBaseline,
    now: u64,
    window_ms: u64,
) -> ([Option<CcciAnomaly>; MAX_ANOMALIES], usize) {
    let mut anomalies: [Option<CcciAnomaly>; MAX_ANOMALIES] = [None; MAX_ANOMALIES];
    let mut count = 0;

    let since = now.saturating_sub(window_ms);

    // Per-channel: check for active channels, rate, and data0.
    for ch in 0..CHANNEL_COUNT {
        let ch_u32 = ch as u32;
        let live_count = log.channel_count_since(ch_u32, since);
        let baseline_stats = &baseline.channels[ch];

        // 1. Unexpected channel active.
        if live_count > 0 && !baseline_stats.active {
            if count < MAX_ANOMALIES {
                anomalies[count] = Some(CcciAnomaly {
                    timestamp: now,
                    channel: ch_u32,
                    kind: AnomalyKind::UnexpectedChannel,
                    observed: live_count,
                    baseline_max: 0,
                });
                count += 1;
            }
            continue;
        }

        if !baseline_stats.active {
            continue;
        }

        // 2. Rate spike > 3x baseline max.
        let spike_threshold = baseline_stats.max_rate.saturating_mul(RATE_SPIKE_FACTOR);
        if live_count > spike_threshold && spike_threshold > 0 {
            if count < MAX_ANOMALIES {
                anomalies[count] = Some(CcciAnomaly {
                    timestamp: now,
                    channel: ch_u32,
                    kind: AnomalyKind::RateSpike,
                    observed: live_count,
                    baseline_max: baseline_stats.max_rate,
                });
                count += 1;
            }
        }

        // 3. data0 out of range -- check the most recent packet on this channel.
        let (older, newer) = log.entries();
        let mut latest_data0: Option<u32> = None;
        for entry in older.iter().chain(newer.iter()) {
            if entry.channel == ch_u32 && entry.timestamp >= since {
                latest_data0 = Some(entry.data0);
            }
        }
        if let Some(d0) = latest_data0 {
            if d0 < baseline_stats.min_data0 || d0 > baseline_stats.max_data0 {
                if count < MAX_ANOMALIES {
                    anomalies[count] = Some(CcciAnomaly {
                        timestamp: now,
                        channel: ch_u32,
                        kind: AnomalyKind::Data0OutOfRange,
                        observed: d0,
                        baseline_max: baseline_stats.max_data0,
                    });
                    count += 1;
                }
            }
        }
    }

    (anomalies, count)
}

// ---------------------------------------------------------------------------
// FirewallMode
// ---------------------------------------------------------------------------

/// Firewall operating mode, determining which channels are allowlisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FirewallMode {
    /// Normal operation: Control, System, Uart1, Ccmni1 channels.
    Daily,
    /// Heightened security: Control, System channels only.
    Sentinel,
    /// Emergency: all channels blocked (empty allowlist).
    Panic,
}

impl fmt::Display for FirewallMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Daily => write!(f, "Daily"),
            Self::Sentinel => write!(f, "Sentinel"),
            Self::Panic => write!(f, "Panic"),
        }
    }
}

// ---------------------------------------------------------------------------
// FirewallVerdict
// ---------------------------------------------------------------------------

/// Result of a firewall evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FirewallVerdict {
    /// Packet is allowed (channel is allowlisted).
    Allow,
    /// Packet is dropped (channel is not allowlisted).
    Drop,
}

impl fmt::Display for FirewallVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Drop => write!(f, "DROP"),
        }
    }
}

// ---------------------------------------------------------------------------
// CcciFirewall
// ---------------------------------------------------------------------------

/// Channel allowlist firewall for the CCCI link.
///
/// Default policy: deny.  Only channels explicitly added to the allowlist
/// are allowed through.  The allowlist is populated based on the current
/// [`FirewallMode`].
///
/// SECURITY: Evaluates before packet dispatch.  Non-allowlisted packets
/// are dropped and audit-logged.
#[must_use]
pub(crate) struct CcciFirewall {
    /// Current firewall mode.
    mode: FirewallMode,
    /// Allowlisted channel numbers.
    allowlist: [u32; MAX_ALLOWLIST],
    /// Number of channels in the allowlist.
    allowlist_len: usize,
    /// Total packets dropped by the firewall.
    drop_count: u64,
    /// Total packets allowed through.
    allow_count: u64,
}

impl CcciFirewall {
    /// Create a new firewall in the given mode.
    pub(crate) fn new(mode: FirewallMode) -> Self {
        let mut fw = Self {
            mode,
            allowlist: [0; MAX_ALLOWLIST],
            allowlist_len: 0,
            drop_count: 0,
            allow_count: 0,
        };
        fw.apply_mode(mode);
        fw
    }

    /// Apply a firewall mode, replacing the allowlist.
    pub(crate) fn apply_mode(&mut self, mode: FirewallMode) {
        self.mode = mode;
        self.allowlist_len = 0;

        match mode {
            FirewallMode::Daily => {
                // Control, System, Uart1, Ccmni1 (TX+RX pairs).
                let channels: &[u32] = &[
                    CcciChannel::ControlTx as u32,
                    CcciChannel::ControlRx as u32,
                    CcciChannel::SystemTx as u32,
                    CcciChannel::SystemRx as u32,
                    CcciChannel::Uart1Tx as u32,
                    CcciChannel::Uart1Rx as u32,
                    CcciChannel::Ccmni1Tx as u32,
                    CcciChannel::Ccmni1Rx as u32,
                ];
                for &ch in channels {
                    if self.allowlist_len < MAX_ALLOWLIST {
                        self.allowlist[self.allowlist_len] = ch;
                        self.allowlist_len += 1;
                    }
                }
            }
            FirewallMode::Sentinel => {
                // Control, System only.
                let channels: &[u32] = &[
                    CcciChannel::ControlTx as u32,
                    CcciChannel::ControlRx as u32,
                    CcciChannel::SystemTx as u32,
                    CcciChannel::SystemRx as u32,
                ];
                for &ch in channels {
                    if self.allowlist_len < MAX_ALLOWLIST {
                        self.allowlist[self.allowlist_len] = ch;
                        self.allowlist_len += 1;
                    }
                }
            }
            FirewallMode::Panic => {
                // Empty allowlist: all channels blocked.
            }
        }
    }

    /// Evaluate a packet against the firewall allowlist.
    ///
    /// Returns [`FirewallVerdict::Allow`] if the channel is allowlisted,
    /// [`FirewallVerdict::Drop`] otherwise.
    pub(crate) fn evaluate(&mut self, channel: u32) -> FirewallVerdict {
        for i in 0..self.allowlist_len {
            if self.allowlist[i] == channel {
                self.allow_count += 1;
                return FirewallVerdict::Allow;
            }
        }
        self.drop_count += 1;
        FirewallVerdict::Drop
    }

    /// Whether a channel is in the allowlist (non-mutating check).
    #[must_use]
    pub(crate) fn is_allowlisted(&self, channel: u32) -> bool {
        self.allowlist[..self.allowlist_len].contains(&channel)
    }

    /// Current firewall mode.
    #[must_use]
    pub(crate) fn mode(&self) -> FirewallMode {
        self.mode
    }

    /// Total packets dropped.
    #[must_use]
    pub(crate) fn drop_count(&self) -> u64 {
        self.drop_count
    }

    /// Total packets allowed.
    #[must_use]
    pub(crate) fn allow_count(&self) -> u64 {
        self.allow_count
    }

    /// Number of channels in the allowlist.
    #[must_use]
    pub(crate) fn allowlist_len(&self) -> usize {
        self.allowlist_len
    }
}

impl fmt::Debug for CcciFirewall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CcciFirewall")
            .field("mode", &self.mode)
            .field("allowlist_len", &self.allowlist_len)
            .field("drop_count", &self.drop_count)
            .field("allow_count", &self.allow_count)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for CcciFirewall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CcciFirewall(mode={}, allowlist={}, dropped={}, allowed={})",
            self.mode, self.allowlist_len, self.drop_count, self.allow_count,
        )
    }
}

// ---------------------------------------------------------------------------
// Modem power cut
// ---------------------------------------------------------------------------

/// PMIC VMODEM LDO register address on MT6739.
///
/// The VMODEM LDO supplies the modem core.  Clearing the enable bit
/// physically removes power from the modem -- a hard kill that software
/// on the modem side cannot prevent or recover from.
///
/// Source: MT6357 PMIC datasheet, VMODEM_CON0 register.
const PMIC_VMODEM_CON0: usize = 0x1000_D000 + 0x0C00;

/// VMODEM enable bit (bit 0 of VMODEM_CON0).
const VMODEM_EN_BIT: u32 = 1 << 0;

/// Execute a hardware modem power cut via PMIC VMODEM LDO disable.
///
/// This is a hard power kill -- the modem core loses all power and cannot
/// recover without a full system reboot.  Intended for:
/// - Critical IMSI catcher threat score
/// - CCCI anomaly exceeding threshold
/// - Manual kill from threat monitor
/// - Panic mode
///
/// # Safety
///
/// PMIC registers must be mapped.  Caller must be in privileged context
/// (kernel mode, IRQs may be disabled).  After this call, all modem
/// communication channels are dead.
///
/// In test builds the MMIO write is skipped (no hardware available).
pub unsafe fn modem_power_cut() {
    // SAFETY: PMIC_VMODEM_CON0 is a valid PMIC register on the MT6739.
    // Clearing the enable bit disables the VMODEM LDO.
    #[cfg(not(test))]
    unsafe {
        crate::mmio::clear_bits(PMIC_VMODEM_CON0, VMODEM_EN_BIT);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CcciLogger tests --

    #[test]
    fn logger_starts_empty() {
        let log = CcciLogger::new();
        assert!(log.is_empty(), "new logger must be empty");
        assert_eq!(log.len(), 0, "new logger has zero entries");
    }

    #[test]
    fn logger_records_entry() {
        let mut log = CcciLogger::new();
        log.record(CcciLogEntry {
            timestamp: 1000,
            channel: 5,
            direction: PacketDirection::Rx,
            data0: 64,
            data1: 0,
            packet_len: 80,
        });
        assert_eq!(log.len(), 1, "one entry after record");
        assert!(!log.is_empty());

        let entry = log.get(0);
        assert!(entry.is_some());
        let e = entry.unwrap_or_else(|| &CcciLogEntry {
            timestamp: 0, channel: 0, direction: PacketDirection::Rx,
            data0: 0, data1: 0, packet_len: 0,
        });
        assert_eq!(e.timestamp, 1000);
        assert_eq!(e.channel, 5);
        assert_eq!(e.packet_len, 80);
    }

    #[test]
    fn logger_wraps_around() {
        let mut log = CcciLogger::new();
        for i in 0..(LOG_CAPACITY + 10) {
            log.record(CcciLogEntry {
                timestamp: i as u64,
                channel: 0,
                direction: PacketDirection::Tx,
                data0: i as u32,
                data1: 0,
                packet_len: 16,
            });
        }
        assert_eq!(log.len(), LOG_CAPACITY, "count capped at capacity");

        // Oldest live entry should be entry #10 (0-9 overwritten).
        let oldest = log.get(0);
        assert!(oldest.is_some());
        let o = oldest.unwrap_or_else(|| &CcciLogEntry {
            timestamp: 0, channel: 0, direction: PacketDirection::Rx,
            data0: 0, data1: 0, packet_len: 0,
        });
        assert_eq!(o.timestamp, 10, "oldest entry after wrap");
    }

    #[test]
    fn logger_channel_count_since() {
        let mut log = CcciLogger::new();
        // 5 packets on channel 3, timestamps 100-500.
        for i in 1..=5 {
            log.record(CcciLogEntry {
                timestamp: i * 100,
                channel: 3,
                direction: PacketDirection::Rx,
                data0: 0,
                data1: 0,
                packet_len: 16,
            });
        }
        // 2 packets on channel 5.
        for i in 1..=2 {
            log.record(CcciLogEntry {
                timestamp: i * 100,
                channel: 5,
                direction: PacketDirection::Rx,
                data0: 0,
                data1: 0,
                packet_len: 16,
            });
        }

        assert_eq!(log.channel_count_since(3, 0), 5, "all ch3 packets");
        assert_eq!(log.channel_count_since(3, 300), 3, "ch3 from t=300");
        assert_eq!(log.channel_count_since(5, 0), 2, "all ch5 packets");
        assert_eq!(log.channel_count_since(7, 0), 0, "no ch7 packets");
    }

    #[test]
    fn logger_entries_chronological() {
        let mut log = CcciLogger::new();
        for i in 0..5u64 {
            log.record(CcciLogEntry {
                timestamp: i * 10,
                channel: 0,
                direction: PacketDirection::Rx,
                data0: 0,
                data1: 0,
                packet_len: 16,
            });
        }

        let (older, newer) = log.entries();
        let all: alloc::vec::Vec<&CcciLogEntry> =
            older.iter().chain(newer.iter()).collect();
        assert_eq!(all.len(), 5);
        for i in 1..all.len() {
            assert!(
                all[i].timestamp >= all[i - 1].timestamp,
                "entries must be chronological"
            );
        }
    }

    #[test]
    fn logger_get_out_of_range() {
        let log = CcciLogger::new();
        assert!(log.get(0).is_none(), "empty logger returns None");
        assert!(log.get(100).is_none(), "out of range returns None");
    }

    #[test]
    fn logger_display() {
        let log = CcciLogger::new();
        let display = alloc::format!("{log}");
        assert!(display.contains("CcciLogger"), "display contains type name");
        assert!(display.contains("0/"), "display shows count");
    }

    // -- ModemBaseline tests --

    #[test]
    fn baseline_empty_logger() {
        let log = CcciLogger::new();
        let baseline = build_baseline(&log, 60_000);
        assert_eq!(baseline.window_start, 0);
        assert_eq!(baseline.window_end, 60_000);
        assert!(
            baseline.channels.iter().all(|c| !c.active),
            "no channels active for empty logger"
        );
    }

    #[test]
    fn baseline_captures_rates() {
        let mut log = CcciLogger::new();
        // 10 packets on channel 0, timestamps 1000-10000.
        for i in 1..=10 {
            log.record(CcciLogEntry {
                timestamp: i * 1000,
                channel: 0,
                direction: PacketDirection::Rx,
                data0: 100,
                data1: 0,
                packet_len: 64,
            });
        }
        // 3 packets on channel 5.
        for i in 1..=3 {
            log.record(CcciLogEntry {
                timestamp: i * 2000,
                channel: 5,
                direction: PacketDirection::Tx,
                data0: 200,
                data1: 0,
                packet_len: 128,
            });
        }

        let baseline = build_baseline(&log, 60_000);

        assert!(baseline.channels[0].active, "ch0 must be active");
        assert_eq!(baseline.channels[0].min_rate, 10, "ch0 rate = 10");
        assert_eq!(baseline.channels[0].max_rate, 10);
        assert_eq!(baseline.channels[0].min_size, 64);
        assert_eq!(baseline.channels[0].max_size, 64);

        assert!(baseline.channels[5].active, "ch5 must be active");
        assert_eq!(baseline.channels[5].min_rate, 3, "ch5 rate = 3");

        assert!(!baseline.channels[10].active, "ch10 must be inactive");
    }

    #[test]
    fn baseline_captures_size_range() {
        let mut log = CcciLogger::new();
        for size in [16u16, 64, 128, 256] {
            log.record(CcciLogEntry {
                timestamp: 1000,
                channel: 2,
                direction: PacketDirection::Rx,
                data0: 0,
                data1: 0,
                packet_len: size,
            });
        }

        let baseline = build_baseline(&log, 60_000);
        let ch2 = &baseline.channels[2];
        assert!(ch2.active);
        assert_eq!(ch2.min_size, 16, "min size = 16");
        assert_eq!(ch2.max_size, 256, "max size = 256");
    }

    #[test]
    fn baseline_captures_data0_range() {
        let mut log = CcciLogger::new();
        for d0 in [10u32, 50, 100, 200] {
            log.record(CcciLogEntry {
                timestamp: 1000,
                channel: 4,
                direction: PacketDirection::Rx,
                data0: d0,
                data1: 0,
                packet_len: 16,
            });
        }

        let baseline = build_baseline(&log, 60_000);
        let ch4 = &baseline.channels[4];
        assert!(ch4.active);
        assert_eq!(ch4.min_data0, 10);
        assert_eq!(ch4.max_data0, 200);
    }

    #[test]
    fn baseline_respects_window() {
        let mut log = CcciLogger::new();
        // Packet outside window.
        log.record(CcciLogEntry {
            timestamp: 100_000, // outside window ending at 60_000
            channel: 0,
            direction: PacketDirection::Rx,
            data0: 0,
            data1: 0,
            packet_len: 16,
        });
        log.record(CcciLogEntry {
            timestamp: 30_000, // inside window [0, 60_000]
            channel: 1,
            direction: PacketDirection::Rx,
            data0: 0,
            data1: 0,
            packet_len: 16,
        });

        let baseline = build_baseline(&log, 60_000);
        assert!(!baseline.channels[0].active, "ch0 is outside window");
        assert!(baseline.channels[1].active, "ch1 is inside window");
    }

    #[test]
    fn baseline_display() {
        let baseline = ModemBaseline::empty();
        let display = alloc::format!("{baseline}");
        assert!(display.contains("ModemBaseline"), "display contains type name");
        assert!(display.contains("0 active"), "empty baseline has 0 active");
    }

    // -- Anomaly detection tests --

    #[test]
    fn anomaly_detects_unexpected_channel() {
        let mut log = CcciLogger::new();
        // Baseline has no activity.
        let baseline = build_baseline(&log, 60_000);

        // Now record traffic on channel 10 (was inactive).
        log.record(CcciLogEntry {
            timestamp: 70_000,
            channel: 10,
            direction: PacketDirection::Rx,
            data0: 0,
            data1: 0,
            packet_len: 16,
        });

        let (anomalies, count) = detect_anomalies(&log, &baseline, 70_000, 60_000);
        assert!(count > 0, "must detect unexpected channel");

        let found = anomalies[..count].iter().flatten().any(|a| {
            a.channel == 10 && a.kind == AnomalyKind::UnexpectedChannel
        });
        assert!(found, "must flag channel 10 as unexpected");
    }

    #[test]
    fn anomaly_detects_rate_spike() {
        let mut log = CcciLogger::new();

        // Baseline: 5 packets on channel 0.
        for i in 1..=5 {
            log.record(CcciLogEntry {
                timestamp: i * 1000,
                channel: 0,
                direction: PacketDirection::Rx,
                data0: 100,
                data1: 0,
                packet_len: 16,
            });
        }
        let baseline = build_baseline(&log, 60_000);
        assert_eq!(baseline.channels[0].max_rate, 5);

        // Now add 20 more packets (total 25 > 5 * 3 = 15).
        for i in 6..=25 {
            log.record(CcciLogEntry {
                timestamp: 60_000 + i * 100,
                channel: 0,
                direction: PacketDirection::Rx,
                data0: 100,
                data1: 0,
                packet_len: 16,
            });
        }

        let (anomalies, count) = detect_anomalies(&log, &baseline, 63_000, 60_000);
        let found = anomalies[..count].iter().flatten().any(|a| {
            a.channel == 0 && a.kind == AnomalyKind::RateSpike
        });
        assert!(found, "must detect rate spike on channel 0");
    }

    #[test]
    fn anomaly_detects_data0_out_of_range() {
        let mut log = CcciLogger::new();

        // Baseline: data0 range [100, 200] on channel 4.
        for d0 in [100u32, 150, 200] {
            log.record(CcciLogEntry {
                timestamp: 1000,
                channel: 4,
                direction: PacketDirection::Rx,
                data0: d0,
                data1: 0,
                packet_len: 16,
            });
        }
        let baseline = build_baseline(&log, 60_000);

        // Now send a packet with data0 = 500 (outside [100, 200]).
        log.record(CcciLogEntry {
            timestamp: 70_000,
            channel: 4,
            direction: PacketDirection::Rx,
            data0: 500,
            data1: 0,
            packet_len: 16,
        });

        let (anomalies, count) = detect_anomalies(&log, &baseline, 70_000, 60_000);
        let found = anomalies[..count].iter().flatten().any(|a| {
            a.channel == 4 && a.kind == AnomalyKind::Data0OutOfRange
        });
        assert!(found, "must detect data0 out of range on channel 4");
    }

    #[test]
    fn anomaly_no_false_positives() {
        let mut log = CcciLogger::new();

        // Baseline: 5 packets on channel 0, data0 = 100.
        for i in 1..=5 {
            log.record(CcciLogEntry {
                timestamp: i * 1000,
                channel: 0,
                direction: PacketDirection::Rx,
                data0: 100,
                data1: 0,
                packet_len: 16,
            });
        }
        let baseline = build_baseline(&log, 60_000);

        // Same traffic pattern continues (within baseline).
        for i in 6..=10 {
            log.record(CcciLogEntry {
                timestamp: i * 1000,
                channel: 0,
                direction: PacketDirection::Rx,
                data0: 100,
                data1: 0,
                packet_len: 16,
            });
        }

        let (_, count) = detect_anomalies(&log, &baseline, 10_000, 60_000);
        assert_eq!(count, 0, "no anomalies for normal traffic");
    }

    // -- CcciFirewall tests --

    #[test]
    fn firewall_daily_allowlist() {
        let fw = CcciFirewall::new(FirewallMode::Daily);
        assert_eq!(fw.mode(), FirewallMode::Daily);
        assert_eq!(fw.allowlist_len(), 8, "Daily: 4 channel pairs = 8");

        // Control, System, Uart1, Ccmni1 channels allowed.
        assert!(fw.is_allowlisted(CcciChannel::ControlTx as u32));
        assert!(fw.is_allowlisted(CcciChannel::ControlRx as u32));
        assert!(fw.is_allowlisted(CcciChannel::SystemTx as u32));
        assert!(fw.is_allowlisted(CcciChannel::SystemRx as u32));
        assert!(fw.is_allowlisted(CcciChannel::Uart1Tx as u32));
        assert!(fw.is_allowlisted(CcciChannel::Uart1Rx as u32));
        assert!(fw.is_allowlisted(CcciChannel::Ccmni1Tx as u32));
        assert!(fw.is_allowlisted(CcciChannel::Ccmni1Rx as u32));

        // Other channels not allowlisted.
        assert!(!fw.is_allowlisted(CcciChannel::FsTx as u32));
        assert!(!fw.is_allowlisted(CcciChannel::MdLogRx as u32));
    }

    #[test]
    fn firewall_sentinel_allowlist() {
        let fw = CcciFirewall::new(FirewallMode::Sentinel);
        assert_eq!(fw.mode(), FirewallMode::Sentinel);
        assert_eq!(fw.allowlist_len(), 4, "Sentinel: 2 channel pairs = 4");

        assert!(fw.is_allowlisted(CcciChannel::ControlTx as u32));
        assert!(fw.is_allowlisted(CcciChannel::ControlRx as u32));
        assert!(fw.is_allowlisted(CcciChannel::SystemTx as u32));
        assert!(fw.is_allowlisted(CcciChannel::SystemRx as u32));

        // Uart1, Ccmni1 blocked in Sentinel.
        assert!(!fw.is_allowlisted(CcciChannel::Uart1Tx as u32));
        assert!(!fw.is_allowlisted(CcciChannel::Ccmni1Tx as u32));
    }

    #[test]
    fn firewall_panic_blocks_all() {
        let fw = CcciFirewall::new(FirewallMode::Panic);
        assert_eq!(fw.mode(), FirewallMode::Panic);
        assert_eq!(fw.allowlist_len(), 0, "Panic: empty allowlist");

        for ch in 0..22u32 {
            assert!(!fw.is_allowlisted(ch), "ch {ch} must be blocked in Panic");
        }
    }

    #[test]
    fn firewall_drops_non_allowlisted() {
        let mut fw = CcciFirewall::new(FirewallMode::Sentinel);

        // Allowlisted channel: allowed.
        let verdict = fw.evaluate(CcciChannel::ControlTx as u32);
        assert_eq!(verdict, FirewallVerdict::Allow);
        assert_eq!(fw.allow_count(), 1);

        // Non-allowlisted channel: dropped.
        let verdict = fw.evaluate(CcciChannel::Uart1Tx as u32);
        assert_eq!(verdict, FirewallVerdict::Drop);
        assert_eq!(fw.drop_count(), 1);
    }

    #[test]
    fn firewall_mode_transition() {
        let mut fw = CcciFirewall::new(FirewallMode::Daily);
        assert_eq!(fw.allowlist_len(), 8);

        fw.apply_mode(FirewallMode::Sentinel);
        assert_eq!(fw.mode(), FirewallMode::Sentinel);
        assert_eq!(fw.allowlist_len(), 4);

        fw.apply_mode(FirewallMode::Panic);
        assert_eq!(fw.mode(), FirewallMode::Panic);
        assert_eq!(fw.allowlist_len(), 0);
    }

    #[test]
    fn firewall_counters_accumulate() {
        let mut fw = CcciFirewall::new(FirewallMode::Sentinel);

        // 3 allows, 2 drops.
        fw.evaluate(CcciChannel::ControlTx as u32);
        fw.evaluate(CcciChannel::ControlRx as u32);
        fw.evaluate(CcciChannel::SystemTx as u32);
        fw.evaluate(CcciChannel::Uart1Tx as u32);
        fw.evaluate(CcciChannel::FsTx as u32);

        assert_eq!(fw.allow_count(), 3);
        assert_eq!(fw.drop_count(), 2);
    }

    #[test]
    fn firewall_display() {
        let fw = CcciFirewall::new(FirewallMode::Daily);
        let display = alloc::format!("{fw}");
        assert!(display.contains("CcciFirewall"), "display contains type name");
        assert!(display.contains("Daily"), "display contains mode");
    }

    // -- PacketDirection tests --

    #[test]
    fn packet_direction_display() {
        assert_eq!(PacketDirection::Tx.to_string(), "TX");
        assert_eq!(PacketDirection::Rx.to_string(), "RX");
    }

    // -- CcciLogEntry Display --

    #[test]
    fn log_entry_display() {
        let entry = CcciLogEntry {
            timestamp: 42000,
            channel: 5,
            direction: PacketDirection::Rx,
            data0: 0x40,
            data1: 0,
            packet_len: 80,
        };
        let display = alloc::format!("{entry}");
        assert!(display.contains("42000"), "display contains timestamp");
        assert!(display.contains("ch=5"), "display contains channel");
        assert!(display.contains("RX"), "display contains direction");
    }

    // -- AnomalyKind Display --

    #[test]
    fn anomaly_kind_display() {
        assert!(
            AnomalyKind::UnexpectedChannel.to_string()
                .contains("unexpected"),
        );
        assert!(
            AnomalyKind::RateSpike.to_string()
                .contains("spike"),
        );
        assert!(
            AnomalyKind::Data0OutOfRange.to_string()
                .contains("range"),
        );
    }

    // -- CcciAnomaly Display --

    #[test]
    fn anomaly_display() {
        let anomaly = CcciAnomaly {
            timestamp: 70_000,
            channel: 10,
            kind: AnomalyKind::UnexpectedChannel,
            observed: 5,
            baseline_max: 0,
        };
        let display = alloc::format!("{anomaly}");
        assert!(display.contains("CcciAnomaly"), "display contains type name");
        assert!(display.contains("ch=10"), "display contains channel");
    }

    // -- FirewallVerdict Display --

    #[test]
    fn firewall_verdict_display() {
        assert_eq!(FirewallVerdict::Allow.to_string(), "ALLOW");
        assert_eq!(FirewallVerdict::Drop.to_string(), "DROP");
    }

    // -- FirewallMode Display --

    #[test]
    fn firewall_mode_display() {
        assert_eq!(FirewallMode::Daily.to_string(), "Daily");
        assert_eq!(FirewallMode::Sentinel.to_string(), "Sentinel");
        assert_eq!(FirewallMode::Panic.to_string(), "Panic");
    }

    // -- ChannelStats Display --

    #[test]
    fn channel_stats_display_active() {
        let stats = ChannelStats {
            min_rate: 5,
            max_rate: 10,
            min_size: 16,
            max_size: 256,
            min_data0: 0x10,
            max_data0: 0xFF,
            active: true,
        };
        let display = alloc::format!("{stats}");
        assert!(display.contains("rate="), "active stats show rate");
        assert!(display.contains("size="), "active stats show size");
    }

    #[test]
    fn channel_stats_display_inactive() {
        let stats = ChannelStats::inactive();
        let display = alloc::format!("{stats}");
        assert_eq!(display, "inactive");
    }
}
