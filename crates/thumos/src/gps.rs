//! GPS kernel adapter for the MT6739 combo chip.
//!
//! - NMEA sentence parser: GGA (fix data) and RMC (recommended minimum)
//! - Sentence buffer: accumulate bytes until `\r\n`, then parse
//! - GPS position and time extraction
//! - Hardware abstraction via `GpsHwOps` trait for testability
//!
//! The checksum framing, coordinate conversion, and fix-quality semantics
//! are canonical in `topos_core` (`no_std` + alloc), shared with the
//! workspace `topos` crate -- the first hand-port and the workspace crate
//! had drifted (#545): the kernel truncated an overflowing fix-quality byte
//! via `as u8` instead of range-checking it (a quality field of `264`
//! wrapped to `8`, a defined code, rather than being rejected), and
//! `topos`'s checksum parser accepted a checksum field with only one hex
//! digit. Neither side bounded latitude/longitude or validated the parsed
//! RMC clock fields before treating them as trustworthy, and the kernel's
//! altitude parser had no sign handling (a below-sea-level reading was
//! silently swallowed). One parser, one set of bounds, both consumers.
//!
//! ## Hardware path
//!
//! The MT6739 GPS hardware is accessed through the WMT combo chip:
//! - `board::CONSYS_BASE = 0x1800_0000` (combo-chip base, `board::m7` #534)
//! - Data path goes through WMT STP framing (kelyphos handles the transport)
//!
//! ## Design
//!
//! No floating-point arithmetic: latitude and longitude are stored as
//! fixed-point integers (degrees * `1_000_000`) to avoid soft-float overhead
//! in a `#![no_std]` kernel without FPU support enabled.
//!
//! ## Integration
//!
//! Boot integration via `kinit.rs` Step 13c. Device node at `/dev/gps0`.

// WHY: hardware driver API not yet wired to upper layers (kinit integration pending).
#![expect(
    dead_code,
    reason = "GPS driver API wired in kinit but not yet called from userspace (#145)"
)]

extern crate alloc;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// MT6739 GPS hardware constants
// ---------------------------------------------------------------------------

/// WMT STP channel identifier for GPS.
const WMT_GPS_CHANNEL: u8 = 0x02;

/// Maximum NMEA sentence length (including $ and *XX\r\n).
const MAX_SENTENCE_LEN: usize = 82;

/// Sentence buffer capacity (two max-length sentences).
const SENTENCE_BUF_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// GPS subsystem errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GpsError {
    /// Hardware did not respond or returned an error status.
    HardwareTimeout,
    /// The GPS hardware is not initialized.
    NotInitialized,
    /// GPS receiver has no fix (insufficient satellites).
    NoFix,
    /// NMEA sentence parse error.
    ParseError,
    /// NMEA checksum mismatch.
    ChecksumMismatch,
    /// Invalid state for the requested operation.
    InvalidState,
}

impl core::fmt::Display for GpsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HardwareTimeout => write!(f, "hardware timeout"),
            Self::NotInitialized => write!(f, "GPS not initialized"),
            Self::NoFix => write!(f, "no GPS fix"),
            Self::ParseError => write!(f, "NMEA parse error"),
            Self::ChecksumMismatch => write!(f, "NMEA checksum mismatch"),
            Self::InvalidState => write!(f, "invalid GPS state"),
        }
    }
}

impl From<topos_core::CoreError> for GpsError {
    fn from(e: topos_core::CoreError) -> Self {
        use topos_core::CoreError as C;
        match e {
            C::NoFix => Self::NoFix,
            C::ChecksumMismatch { .. } => Self::ChecksumMismatch,
            // WHY a catch-all: CoreError is `#[non_exhaustive]`; an
            // unrecognised parse failure becoming ParseError rejects the
            // sentence, which is the fail-closed direction -- GPS position
            // is a location trust boundary, not a display convenience.
            _ => Self::ParseError,
        }
    }
}

// ---------------------------------------------------------------------------
// GPS state machine
// ---------------------------------------------------------------------------

/// GPS receiver lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum GpsState {
    /// GPS radio is off.
    #[default]
    Off,
    /// Searching for satellites (no fix yet).
    Searching,
    /// Fix acquired, position available.
    FixAcquired,
    /// A fatal error occurred.
    Error(GpsError),
}

impl core::fmt::Display for GpsState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Searching => write!(f, "searching"),
            Self::FixAcquired => write!(f, "fix acquired"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// GPS position (fixed-point, no floating-point)
// ---------------------------------------------------------------------------

/// GPS position with fixed-point coordinates.
///
/// Latitude and longitude are stored as microdegrees (degrees * `1_000_000`)
/// to avoid floating-point arithmetic in the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GpsPosition {
    /// Latitude in microdegrees. Positive = North, negative = South.
    pub latitude: i64,
    /// Longitude in microdegrees. Positive = East, negative = West.
    pub longitude: i64,
    /// Altitude above mean sea level in millimeters. `None` when the
    /// sentence's altitude field was absent or malformed -- distinct from
    /// an actual sea-level (`Some(0)`) reading (#545: the prior
    /// representation defaulted a malformed field to `0`, indistinguishable
    /// from sea level, and could not represent a below-sea-level reading
    /// at all).
    pub altitude_mm: Option<i32>,
    /// Fix quality indicator.
    pub fix_quality: topos_core::FixQuality,
    /// Number of satellites in use.
    pub satellite_count: u8,
}

impl From<topos_core::Fix> for GpsPosition {
    fn from(fix: topos_core::Fix) -> Self {
        Self {
            latitude: fix.position.lat_udeg,
            longitude: fix.position.lon_udeg,
            altitude_mm: fix.altitude_mm,
            fix_quality: fix.quality,
            satellite_count: fix.satellite_count,
        }
    }
}

impl core::fmt::Display for GpsPosition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Display as degrees with 6 decimal places (microdegree precision).
        let lat_deg = self.latitude / 1_000_000;
        let lat_frac = (self.latitude % 1_000_000).unsigned_abs();
        let lon_deg = self.longitude / 1_000_000;
        let lon_frac = (self.longitude % 1_000_000).unsigned_abs();
        write!(f, "{lat_deg}.{lat_frac:06}, {lon_deg}.{lon_frac:06}")
    }
}

/// UTC date and time extracted from RMC sentences.
///
/// Used by the clock module to synchronize the system clock from GPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GpsTime {
    /// Year (full, e.g., 2026).
    pub year: u16,
    /// Month (1-12).
    pub month: u8,
    /// Day of month (1-31).
    pub day: u8,
    /// Hour (0-23).
    pub hour: u8,
    /// Minute (0-59).
    pub minute: u8,
    /// Second (0-59).
    pub second: u8,
}

impl From<topos_core::DateTime> for GpsTime {
    fn from(dt: topos_core::DateTime) -> Self {
        Self {
            year: dt.year,
            month: dt.month,
            day: dt.day,
            hour: dt.hour,
            minute: dt.minute,
            second: dt.second,
        }
    }
}

impl core::fmt::Display for GpsTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second,
        )
    }
}

impl GpsTime {
    /// Convert to a rough Unix epoch seconds estimate.
    ///
    /// Uses a simplified calculation (no leap second correction).
    /// Accurate enough for clock hierarchy purposes.
    #[must_use]
    pub(crate) fn to_epoch_secs(self) -> u64 {
        // Days from Unix epoch (1970-01-01) to the given date.
        // Simplified: 365.25 days/year average, 30.44 days/month average.
        let years_since_epoch = self.year.saturating_sub(1970) as u64;
        let months = self.month.saturating_sub(1) as u64;
        let days = self.day.saturating_sub(1) as u64;

        // Approximate calculation — sufficient for clock hierarchy ordering.
        let total_days = years_since_epoch * 365 + years_since_epoch / 4 + months * 30 + days;

        total_days * 86400 + self.hour as u64 * 3600 + self.minute as u64 * 60 + self.second as u64
    }
}

// ---------------------------------------------------------------------------
// NMEA parsing (delegates to topos_core; see the module doc for #545)
// ---------------------------------------------------------------------------

/// Parse a GGA sentence (Global Positioning System Fix Data).
///
/// # Errors
///
/// Returns `GpsError::ChecksumMismatch` if the checksum is invalid.
/// Returns `GpsError::NoFix` if fix quality is 0 or an undefined code.
/// Returns `GpsError::ParseError` if the sentence cannot be parsed.
pub(crate) fn parse_gga(sentence: &[u8]) -> Result<GpsPosition, GpsError> {
    Ok(topos_core::parse_gga(sentence)?.into())
}

/// Parse an RMC sentence (Recommended Minimum Navigation Information).
///
/// # Errors
///
/// Returns `GpsError::ChecksumMismatch` if the checksum is invalid.
/// Returns `GpsError::NoFix` if status is 'V' (void).
/// Returns `GpsError::ParseError` if the sentence cannot be parsed.
pub(crate) fn parse_rmc(sentence: &[u8]) -> Result<(GpsPosition, GpsTime), GpsError> {
    let (fix, time) = topos_core::parse_rmc(sentence)?;
    Ok((fix.into(), time.into()))
}

// ---------------------------------------------------------------------------
// Sentence buffer
// ---------------------------------------------------------------------------

/// Accumulates incoming bytes until a complete NMEA sentence (`\r\n`) is found.
pub(crate) struct SentenceBuffer {
    /// Internal byte buffer.
    buf: Vec<u8>,
}

impl SentenceBuffer {
    /// Create a new empty sentence buffer.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::with_capacity(SENTENCE_BUF_CAPACITY),
        }
    }

    /// Feed bytes into the buffer.
    pub(crate) fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        // Prevent unbounded growth.
        if self.buf.len() > SENTENCE_BUF_CAPACITY {
            // Discard oldest data, keeping the last MAX_SENTENCE_LEN bytes.
            let keep_from = self.buf.len() - MAX_SENTENCE_LEN;
            self.buf.drain(..keep_from);
        }
    }

    /// Extract the next complete sentence, if available.
    ///
    /// A sentence starts with `$` and ends with `\r\n`.
    /// Returns the sentence bytes (including `$` and checksum) and removes
    /// them from the buffer.
    pub(crate) fn take_sentence(&mut self) -> Option<Vec<u8>> {
        // Find \r\n.
        let crlf_pos = self.buf.windows(2).position(|w| w == b"\r\n")?;

        // Find the $ that starts this sentence (search backwards from crlf).
        let dollar_pos = self.buf[..crlf_pos].iter().rposition(|&b| b == b'$')?;

        // Extract the sentence (including $ through the chars before \r\n).
        let sentence = self.buf[dollar_pos..crlf_pos].to_vec();

        // Remove consumed bytes (including the \r\n).
        self.buf.drain(..crlf_pos + 2);

        Some(sentence)
    }

    /// Return the current buffer length.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Return true if the buffer is empty.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Hardware abstraction trait
// ---------------------------------------------------------------------------

/// Hardware operations trait for GPS driver abstraction.
///
/// Allows test-friendly mocking of WMT STP transport access.
pub(crate) trait GpsHwOps {
    /// Read raw bytes from the GPS data path.
    fn read_data(&mut self, buf: &mut [u8]) -> usize;

    /// Power on the GPS subsystem within the combo chip.
    fn power_on(&mut self) -> Result<(), GpsError>;

    /// Power off the GPS subsystem.
    fn power_off(&mut self) -> Result<(), GpsError>;
}

// ---------------------------------------------------------------------------
// Real hardware implementation
// ---------------------------------------------------------------------------

/// Real GPS hardware access via WMT STP on the MT6739 combo chip.
#[cfg(not(feature = "qemu"))]
pub(crate) struct GpsHw {
    /// WMT combo-chip MMIO base address.
    consys_base: usize,
}

#[cfg(not(feature = "qemu"))]
impl GpsHw {
    /// Create a new GPS hardware handle.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            consys_base: crate::board::CONSYS_BASE,
        }
    }
}

#[cfg(not(feature = "qemu"))]
impl GpsHwOps for GpsHw {
    fn read_data(&mut self, _buf: &mut [u8]) -> usize {
        // TODO(#129)[deliberate-prudent]: implement WMT STP frame RX for GPS channel.
        0
    }

    fn power_on(&mut self) -> Result<(), GpsError> {
        // WHY (#542): fail closed until the WMT power-on command is actually
        // sent and acknowledged (TODO #129) — returning Ok(()) here let boot
        // believe a GPS radio was ready when nothing was ever powered on.
        Err(GpsError::HardwareTimeout)
    }

    fn power_off(&mut self) -> Result<(), GpsError> {
        // TODO(#129)[deliberate-prudent]: send WMT power-off command for GPS subsystem.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// GPS receiver
// ---------------------------------------------------------------------------

/// GPS receiver managing the GPS data path from the WMT combo chip.
///
/// Accumulates NMEA data, parses sentences, and maintains the current
/// position and time fix.
pub(crate) struct GpsReceiver<H: GpsHwOps> {
    /// Current receiver state.
    state: GpsState,
    /// Hardware abstraction.
    hw: H,
    /// NMEA sentence accumulator.
    sentence_buf: SentenceBuffer,
    /// Most recent position fix.
    last_position: Option<GpsPosition>,
    /// Most recent time fix.
    last_time: Option<GpsTime>,
}

impl<H: GpsHwOps> GpsReceiver<H> {
    /// Create a new GPS receiver with the given hardware backend.
    #[must_use]
    pub(crate) fn new(hw: H) -> Self {
        Self {
            state: GpsState::Off,
            hw,
            sentence_buf: SentenceBuffer::new(),
            last_position: None,
            last_time: None,
        }
    }

    /// Return the current receiver state.
    #[must_use]
    pub(crate) fn state(&self) -> GpsState {
        self.state
    }

    /// Return the most recent position fix, if available.
    #[must_use]
    pub(crate) fn position(&self) -> Option<&GpsPosition> {
        self.last_position.as_ref()
    }

    /// Return the most recent GPS time, if available.
    #[must_use]
    pub(crate) fn time(&self) -> Option<&GpsTime> {
        self.last_time.as_ref()
    }

    /// Initialize the GPS receiver: power on and begin searching.
    pub(crate) fn init(&mut self) -> Result<(), GpsError> {
        if self.state != GpsState::Off {
            return Err(GpsError::InvalidState);
        }

        self.hw.power_on()?;
        self.state = GpsState::Searching;
        Ok(())
    }

    /// Poll for new NMEA data and parse any complete sentences.
    ///
    /// Should be called periodically. Updates the position and time
    /// fields when valid sentences are received.
    pub(crate) fn poll(&mut self) {
        if self.state != GpsState::Searching && self.state != GpsState::FixAcquired {
            return;
        }

        // Read available data from hardware.
        let mut read_buf = [0u8; 128];
        let n = self.hw.read_data(&mut read_buf);
        if n > 0 {
            self.sentence_buf.feed(&read_buf[..n]);
        }

        // Process all complete sentences.
        while let Some(sentence) = self.sentence_buf.take_sentence() {
            self.process_sentence(&sentence);
        }
    }

    /// Process a single NMEA sentence.
    fn process_sentence(&mut self, sentence: &[u8]) {
        // Determine sentence type from the talker+type field.
        if sentence.len() < 6 {
            return;
        }

        // Skip the $ prefix for type matching.
        let type_field = &sentence[1..];

        if (type_field.starts_with(b"GPGGA") || type_field.starts_with(b"GNGGA"))
            && let Ok(pos) = parse_gga(sentence)
        {
            self.last_position = Some(pos);
            self.state = GpsState::FixAcquired;
        } else if (type_field.starts_with(b"GPRMC") || type_field.starts_with(b"GNRMC"))
            && let Ok((pos, time)) = parse_rmc(sentence)
        {
            self.last_position = Some(pos);
            self.last_time = Some(time);
            self.state = GpsState::FixAcquired;
        }
    }

    /// Shut down the GPS receiver.
    ///
    /// Clears the last known position/time fix and any partially
    /// accumulated NMEA bytes so a subsequent `init()` does not resume
    /// with stale data left over from before shutdown.
    pub(crate) fn shutdown(&mut self) -> Result<(), GpsError> {
        self.hw.power_off()?;
        self.state = GpsState::Off;
        self.last_position = None;
        self.last_time = None;
        self.sentence_buf = SentenceBuffer::new();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mock hardware for tests
// ---------------------------------------------------------------------------

/// Mock GPS hardware for unit testing.
#[cfg(test)]
pub struct MockGpsHw {
    /// Data to return from `read_data`.
    pub data_queue: Vec<u8>,
    /// Whether `power_on` succeeds.
    pub power_on_ok: bool,
}

#[cfg(test)]
impl MockGpsHw {
    /// Create a new mock with default settings.
    pub fn new() -> Self {
        Self {
            data_queue: Vec::new(),
            power_on_ok: true,
        }
    }
}

#[cfg(test)]
impl GpsHwOps for MockGpsHw {
    fn read_data(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.data_queue.len());
        if n > 0 {
            buf[..n].copy_from_slice(&self.data_queue[..n]);
            self.data_queue.drain(..n);
        }
        n
    }

    fn power_on(&mut self) -> Result<(), GpsError> {
        if self.power_on_ok {
            Ok(())
        } else {
            Err(GpsError::HardwareTimeout)
        }
    }

    fn power_off(&mut self) -> Result<(), GpsError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- GGA parsing --

    #[test]
    fn parse_gga_extracts_position() {
        let sentence = b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76";
        let pos = parse_gga(sentence);
        assert!(pos.is_ok(), "valid GGA sentence must parse successfully");
        let pos = pos.unwrap_or_default();
        assert_eq!(
            pos.fix_quality,
            topos_core::FixQuality::Gps,
            "fix quality must be GPS"
        );
        assert_eq!(pos.satellite_count, 8, "satellite count must be 8");
        // 53 degrees 21.6802 minutes N = ~53361336 microdegrees
        assert!(
            (pos.latitude - 53_361_336).abs() < 100,
            "latitude must be ~53361336 microdegrees, got {}",
            pos.latitude
        );
        // 6 degrees 30.3372 minutes W = ~-6505620 microdegrees (negative for W)
        assert!(pos.longitude < 0, "longitude must be negative for West");
        assert_eq!(
            pos.altitude_mm,
            Some(61_700),
            "altitude must parse to Some(61700) mm"
        );
    }

    #[test]
    fn parse_gga_rejects_bad_checksum() {
        let sentence = b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*FF";
        assert_eq!(
            parse_gga(sentence),
            Err(GpsError::ChecksumMismatch),
            "a corrupted checksum must propagate through the topos_core \
             delegation as GpsError::ChecksumMismatch"
        );
    }

    #[test]
    fn parse_gga_rejects_undefined_and_overflowing_quality_code() {
        // #545: the kernel previously widened this field via a truncating
        // `as u8` cast, so a quality value of 264 (which does not fit u8)
        // wrapped to 8 -- a DEFINED quality code -- and was accepted as a
        // fix. Converged onto topos_core's saturate-to-default parse: an
        // overflowing or undefined quality code must resolve to NoFix.
        let sentence =
            nmea_sentence(b"GPGGA,092750.000,5321.6802,N,00630.3372,W,264,8,1.03,61.7,M,55.2,M,,");
        assert_eq!(
            parse_gga(&sentence),
            Err(GpsError::NoFix),
            "a quality field of 264 must never resolve to a defined (accepted) fix"
        );
    }

    // -- RMC parsing --

    #[test]
    fn parse_rmc_extracts_time() {
        let sentence = b"$GPRMC,092750.000,A,5321.6802,N,00630.3372,W,0.02,31.66,280511,,,A*43";
        let result = parse_rmc(sentence);
        assert!(result.is_ok(), "valid RMC sentence must parse successfully");
        let (_, time) = result.unwrap_or_default();
        assert_eq!(time.hour, 9, "hour must be 09");
        assert_eq!(time.minute, 27, "minute must be 27");
        assert_eq!(time.second, 50, "second must be 50");
        assert_eq!(time.day, 28, "day must be 28");
        assert_eq!(time.month, 5, "month must be 05");
        assert_eq!(time.year, 2011, "year must be 2011");
    }

    #[test]
    fn parse_rmc_void_status_returns_no_fix() {
        // status field 'V' (void) must be rejected even though every
        // other field is well-formed and passes checksum validation.
        // Build with a computed checksum so the void-status branch is
        // reached rather than a checksum ParseError.
        let sentence =
            nmea_sentence(b"GPRMC,092750.000,V,5321.6802,N,00630.3372,W,0.02,31.66,280511,,,A");
        let result = parse_rmc(&sentence);
        assert_eq!(
            result,
            Err(GpsError::NoFix),
            "RMC status 'V' (void) must return NoFix"
        );
    }

    // -- GGA no-fix error --

    #[test]
    fn parse_gga_returns_error_on_no_fix() {
        let sentence = b"$GPGGA,092750.000,,,,,,0,0,,,,,,,*6D";
        let result = parse_gga(sentence);
        assert_eq!(
            result,
            Err(GpsError::NoFix),
            "GGA with fix quality 0 must return NoFix error"
        );
    }

    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    /// Build a valid-checksum NMEA sentence "$<body>*<XX>" (no CRLF) for
    /// tests that need to get past checksum validation before reaching a
    /// deeper parse branch.
    fn nmea_sentence(body: &[u8]) -> Vec<u8> {
        let checksum = topos_core::compute_checksum(body);
        let mut sentence = Vec::new();
        sentence.push(b'$');
        sentence.extend_from_slice(body);
        sentence.push(b'*');
        sentence.push(HEX[(checksum >> 4) as usize]);
        sentence.push(HEX[(checksum & 0xF) as usize]);
        sentence
    }

    #[test]
    fn parse_gga_rejects_fewer_than_ten_fields() {
        let sentence = nmea_sentence(b"GPGGA,1,2,3");
        let result = parse_gga(&sentence);
        assert_eq!(
            result,
            Err(GpsError::ParseError),
            "a GGA sentence with fewer than 10 fields must be ParseError"
        );
    }

    #[test]
    fn parse_rmc_rejects_fewer_than_ten_fields() {
        let sentence = nmea_sentence(b"GPRMC,1,A,2");
        let result = parse_rmc(&sentence);
        assert_eq!(
            result,
            Err(GpsError::ParseError),
            "an RMC sentence with fewer than 10 fields must be ParseError"
        );
    }

    // -- Sentence buffer --

    #[test]
    fn sentence_buffer_accumulates_bytes() {
        let mut buf = SentenceBuffer::new();
        assert!(buf.is_empty(), "new buffer must be empty");

        // Feed partial sentence.
        buf.feed(b"$GPGGA,0927");
        assert_eq!(buf.len(), 11, "buffer must accumulate 11 bytes");
        assert!(
            buf.take_sentence().is_none(),
            "incomplete sentence must not be returned"
        );

        // Complete the sentence.
        buf.feed(b"50.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76\r\n");
        let sentence = buf.take_sentence();
        assert!(sentence.is_some(), "complete sentence must be returned");
        let sentence = sentence.unwrap_or_default();
        assert!(
            sentence.starts_with(b"$GPGGA"),
            "sentence must start with $GPGGA"
        );
    }

    #[test]
    fn sentence_buffer_handles_multiple_sentences() {
        let mut buf = SentenceBuffer::new();
        buf.feed(
            b"$GPGGA,1,2,N,3,E,1,4,1.0,10.0,M,0,M,,*53\r\n$GPRMC,1,A,2,N,3,E,0,0,010170,,,A*00\r\n",
        );

        let first = buf.take_sentence();
        assert!(first.is_some(), "first sentence must be extractable");

        let second = buf.take_sentence();
        assert!(second.is_some(), "second sentence must be extractable");
    }

    #[test]
    fn sentence_buffer_feed_truncates_and_preserves_newest_bytes() {
        let mut buf = SentenceBuffer::new();

        // Push a long run of un-terminated filler bytes past capacity,
        // then a complete valid sentence. If feed() truncated the newest
        // bytes instead of the oldest, the trailing sentence would be lost.
        let filler = [b'X'; 300];
        buf.feed(&filler);
        assert_eq!(
            buf.len(),
            MAX_SENTENCE_LEN,
            "feed() must truncate to MAX_SENTENCE_LEN once SENTENCE_BUF_CAPACITY is exceeded"
        );

        buf.feed(b"$GPGGA,1,2,N,3,E,1,4,1.0,10.0,M,0,M,,*53\r\n");
        let sentence = buf.take_sentence();
        assert!(
            sentence.is_some(),
            "a sentence fed after overflow-truncation must still be extractable, \
             proving the truncation discarded the oldest bytes, not the newest"
        );
    }

    // -- GPS receiver --

    #[test]
    fn receiver_starts_off() {
        let hw = MockGpsHw::new();
        let receiver = GpsReceiver::new(hw);
        assert_eq!(
            receiver.state(),
            GpsState::Off,
            "new receiver must start in Off state"
        );
        assert!(receiver.position().is_none(), "no position before init");
    }

    #[test]
    fn receiver_init_transitions_to_searching() {
        let hw = MockGpsHw::new();
        let mut receiver = GpsReceiver::new(hw);
        let result = receiver.init();
        assert!(result.is_ok(), "init must succeed");
        assert_eq!(
            receiver.state(),
            GpsState::Searching,
            "state must be Searching after init"
        );
    }

    // -- GpsTime epoch conversion --

    #[test]
    fn gps_time_to_epoch_is_nonzero_for_2011() {
        let time = GpsTime {
            year: 2011,
            month: 5,
            day: 28,
            hour: 9,
            minute: 27,
            second: 50,
        };
        let epoch = time.to_epoch_secs();
        // 2011-05-28 09:27:50 UTC is roughly 1306573670 unix epoch seconds.
        // Our simplified calculation won't be exact, but should be in the right ballpark.
        assert!(
            epoch > 1_300_000_000 && epoch < 1_320_000_000,
            "epoch for 2011-05-28 must be approximately 1306573670, got {}",
            epoch
        );
    }

    // --- Error path coverage ---

    #[test]
    fn init_on_failed_hw_returns_timeout() {
        let mut hw = MockGpsHw::new();
        hw.power_on_ok = false;
        let mut receiver = GpsReceiver::new(hw);
        let result = receiver.init();
        assert_eq!(
            result,
            Err(GpsError::HardwareTimeout),
            "init with failing hardware must return HardwareTimeout"
        );
    }

    #[test]
    fn production_gps_hw_fails_closed_without_wmt_transport() {
        let mut receiver = GpsReceiver::new(GpsHw::new());
        assert!(
            receiver.init().is_err(),
            "GpsHw::power_on must fail closed until the WMT power command exists (#542)"
        );
        assert_eq!(
            receiver.state(),
            GpsState::Off,
            "a failed power_on must leave the receiver Off, never Searching"
        );
    }

    #[test]
    fn process_in_wrong_state_returns_invalid_state() {
        let hw = MockGpsHw::new();
        let mut receiver = GpsReceiver::new(hw);
        // Already in Off state, init again should work (first init).
        receiver.init().expect("first init must succeed");
        // Second init while in Searching state must return InvalidState.
        let result = receiver.init();
        assert_eq!(
            result,
            Err(GpsError::InvalidState),
            "init while already initialized must return InvalidState"
        );
    }

    #[test]
    fn shutdown_clears_stale_position_and_time() {
        let hw = MockGpsHw::new();
        let mut receiver = GpsReceiver::new(hw);
        receiver.init().expect("init must succeed");
        receiver.process_sentence(
            b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76",
        );
        assert!(
            receiver.position().is_some(),
            "position must be set after processing a valid GGA sentence"
        );

        receiver.shutdown().expect("shutdown must succeed");
        assert!(
            receiver.position().is_none(),
            "shutdown must clear the last known position"
        );
        assert!(
            receiver.time().is_none(),
            "shutdown must clear the last known time"
        );
    }

    #[test]
    fn poll_reads_hw_data_and_updates_position_end_to_end() {
        let mut hw = MockGpsHw::new();
        hw.data_queue =
            b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76\r\n".to_vec();
        let mut receiver = GpsReceiver::new(hw);
        receiver.init().expect("init must succeed");
        assert_eq!(receiver.state(), GpsState::Searching);

        receiver.poll();

        assert_eq!(
            receiver.state(),
            GpsState::FixAcquired,
            "poll() must drive the full read -> buffer -> parse -> state pipeline"
        );
        assert!(
            receiver.position().is_some(),
            "poll() must populate the position fix from hardware data end-to-end"
        );
    }
}
