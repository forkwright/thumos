//! GPS kernel adapter for the MT6739 combo chip.
//!
//! Ports NMEA parsing from `crates/topos/src/` (nmea.rs, position.rs)
//! into the kernel context:
//! - NMEA sentence parser: GGA (fix data) and RMC (recommended minimum)
//! - Sentence buffer: accumulate bytes until `\r\n`, then parse
//! - GPS position and time extraction
//! - Hardware abstraction via `GpsHwOps` trait for testability
//!
//! ## Hardware path
//!
//! The MT6739 GPS hardware is accessed through the WMT combo chip:
//! - `MT6739_CONSYS = 0x1800_0000` (combo-chip base)
//! - Data path goes through WMT STP framing (kelyphos handles the transport)
//!
//! ## Design
//!
//! No floating-point arithmetic: latitude and longitude are stored as
//! fixed-point integers (degrees * 1_000_000) to avoid soft-float overhead
//! in a `#![no_std]` kernel without FPU support enabled.
//!
//! ## Integration
//!
//! Boot integration via `kinit.rs` Step 13c. Device node at `/dev/gps0`.

// WHY: hardware driver API not yet wired to upper layers (kinit integration pending).
#![expect(dead_code, reason = "GPS driver API wired in kinit but not yet called from userspace")]

extern crate alloc;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// MT6739 GPS hardware constants
// ---------------------------------------------------------------------------

/// WMT combo-chip (CONSYS) MMIO base address.
const MT6739_CONSYS: usize = 0x1800_0000;

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

// ---------------------------------------------------------------------------
// GPS position (fixed-point, no floating-point)
// ---------------------------------------------------------------------------

/// GPS position with fixed-point coordinates.
///
/// Latitude and longitude are stored as microdegrees (degrees * 1_000_000)
/// to avoid floating-point arithmetic in the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GpsPosition {
    /// Latitude in microdegrees. Positive = North, negative = South.
    pub latitude: i64,
    /// Longitude in microdegrees. Positive = East, negative = West.
    pub longitude: i64,
    /// Altitude above mean sea level in millimeters. `0` if unavailable.
    pub altitude_mm: i32,
    /// Fix quality indicator (0 = no fix, 1 = GPS, 2 = DGPS, etc.).
    pub fix_quality: u8,
    /// Number of satellites in use.
    pub satellite_count: u8,
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

impl GpsTime {
    /// Convert to a rough Unix epoch seconds estimate.
    ///
    /// Uses a simplified calculation (no leap second correction).
    /// Accurate enough for clock hierarchy purposes.
    #[must_use]
    pub fn to_epoch_secs(self) -> u64 {
        // Days from Unix epoch (1970-01-01) to the given date.
        // Simplified: 365.25 days/year average, 30.44 days/month average.
        let years_since_epoch = self.year.saturating_sub(1970) as u64;
        let months = self.month.saturating_sub(1) as u64;
        let days = self.day.saturating_sub(1) as u64;

        // Approximate calculation — sufficient for clock hierarchy ordering.
        let total_days = years_since_epoch * 365 + years_since_epoch / 4
            + months * 30 + days;

        total_days * 86400 + self.hour as u64 * 3600
            + self.minute as u64 * 60 + self.second as u64
    }
}

// ---------------------------------------------------------------------------
// NMEA parsing (no_std, no floating-point)
// ---------------------------------------------------------------------------

/// Validate NMEA checksum. The checksum is the XOR of all bytes between '$' and '*'.
fn validate_checksum(sentence: &[u8]) -> Result<(), GpsError> {
    // Find $ and * positions.
    let start = sentence.iter().position(|&b| b == b'$')
        .ok_or(GpsError::ParseError)?;
    let star = sentence.iter().position(|&b| b == b'*')
        .ok_or(GpsError::ParseError)?;

    if star <= start + 1 || star + 3 > sentence.len() {
        return Err(GpsError::ParseError);
    }

    // Compute XOR checksum of bytes between $ and *.
    let mut checksum: u8 = 0;
    for &b in &sentence[start + 1..star] {
        checksum ^= b;
    }

    // Parse the expected checksum (two hex chars after *).
    let expected = parse_hex_byte(sentence[star + 1], sentence[star + 2])
        .ok_or(GpsError::ChecksumMismatch)?;

    if checksum == expected {
        Ok(())
    } else {
        Err(GpsError::ChecksumMismatch)
    }
}

/// Parse a single hex digit to its numeric value.
const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Parse two hex character bytes into a single u8.
fn parse_hex_byte(hi: u8, lo: u8) -> Option<u8> {
    let h = hex_digit(hi)?;
    let l = hex_digit(lo)?;
    Some(h * 16 + l)
}

/// Split an NMEA sentence body (between $ and *) into comma-separated fields.
///
/// Returns a vector of byte slices.
fn split_fields(body: &[u8]) -> Vec<&[u8]> {
    let mut fields = Vec::new();
    let mut start = 0;
    for (i, &b) in body.iter().enumerate() {
        if b == b',' {
            fields.push(&body[start..i]);
            start = i + 1;
        }
    }
    fields.push(&body[start..]);
    fields
}

/// Parse NMEA latitude field (DDMM.MMMM format) to microdegrees.
///
/// Returns microdegrees (degrees * 1_000_000). Negated if hemisphere is 'S'.
fn parse_lat(value: &[u8], hemisphere: &[u8]) -> Result<i64, GpsError> {
    if value.len() < 4 {
        return Err(GpsError::ParseError);
    }

    let microdeg = parse_nmea_coord(value, 2)?;

    if hemisphere == b"S" {
        Ok(-microdeg)
    } else {
        Ok(microdeg)
    }
}

/// Parse NMEA longitude field (DDDMM.MMMM format) to microdegrees.
fn parse_lon(value: &[u8], hemisphere: &[u8]) -> Result<i64, GpsError> {
    if value.len() < 5 {
        return Err(GpsError::ParseError);
    }

    let microdeg = parse_nmea_coord(value, 3)?;

    if hemisphere == b"W" {
        Ok(-microdeg)
    } else {
        Ok(microdeg)
    }
}

/// Parse an NMEA coordinate (DDDMM.MMMM) into microdegrees.
///
/// `deg_digits` is 2 for latitude, 3 for longitude.
fn parse_nmea_coord(value: &[u8], deg_digits: usize) -> Result<i64, GpsError> {
    if value.len() < deg_digits + 2 {
        return Err(GpsError::ParseError);
    }

    let degrees = parse_int(&value[..deg_digits]).ok_or(GpsError::ParseError)? as i64;
    let minutes_part = &value[deg_digits..];

    // Parse minutes as integer + fractional parts.
    // Find the decimal point.
    let dot_pos = minutes_part.iter().position(|&b| b == b'.');

    let (int_part, frac_part) = match dot_pos {
        Some(pos) => (&minutes_part[..pos], &minutes_part[pos + 1..]),
        None => (minutes_part, &[] as &[u8]),
    };

    let minutes_int = parse_int(int_part).ok_or(GpsError::ParseError)? as i64;

    // Parse fractional part, scaled to 4 decimal places.
    let frac_val = if frac_part.is_empty() {
        0i64
    } else {
        let raw = parse_int(frac_part).ok_or(GpsError::ParseError)? as i64;
        // Scale to 4 digits (10000).
        let frac_len = frac_part.len() as u32;
        if frac_len < 4 {
            raw * 10i64.pow(4 - frac_len)
        } else if frac_len > 4 {
            raw / 10i64.pow(frac_len - 4)
        } else {
            raw
        }
    };

    // minutes = minutes_int + frac_val / 10000
    // microdegrees = (degrees + minutes / 60) * 1_000_000
    //              = degrees * 1_000_000 + (minutes_int * 10000 + frac_val) * 1_000_000 / (60 * 10000)
    let minutes_scaled = minutes_int * 10000 + frac_val;
    let microdeg = degrees * 1_000_000 + minutes_scaled * 1_000_000 / 600_000;

    Ok(microdeg)
}

/// Parse a byte slice of ASCII digits into a u32.
fn parse_int(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut result: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(result)
}

/// Parse a fixed-point decimal number from bytes, returning value * 10^scale.
fn parse_fixed_point(bytes: &[u8], scale: u32) -> Option<i64> {
    let dot_pos = bytes.iter().position(|&b| b == b'.');
    let (int_bytes, frac_bytes) = match dot_pos {
        Some(pos) => (&bytes[..pos], &bytes[pos + 1..]),
        None => (bytes, &[] as &[u8]),
    };

    let int_val = parse_int(int_bytes)? as i64;
    let frac_val = if frac_bytes.is_empty() {
        0i64
    } else {
        parse_int(frac_bytes)? as i64
    };

    let frac_len = frac_bytes.len() as u32;
    let frac_scaled = if frac_len < scale {
        frac_val * 10i64.pow(scale - frac_len)
    } else if frac_len > scale {
        frac_val / 10i64.pow(frac_len - scale)
    } else {
        frac_val
    };

    Some(int_val * 10i64.pow(scale) + frac_scaled)
}

/// Parse altitude from NMEA field (meters with decimal) into millimeters.
fn parse_altitude_mm(bytes: &[u8]) -> Option<i32> {
    if bytes.is_empty() {
        return None;
    }
    // Parse as fixed-point with 3 decimal places (millimeters).
    let val = parse_fixed_point(bytes, 3)?;
    // Clamp to i32 range.
    if val > i32::MAX as i64 || val < i32::MIN as i64 {
        return None;
    }
    Some(val as i32)
}

/// Parse a GGA sentence (Global Positioning System Fix Data).
///
/// Extracts position, fix quality, and satellite count.
///
/// # Errors
///
/// Returns `GpsError::ChecksumMismatch` if the checksum is invalid.
/// Returns `GpsError::NoFix` if fix quality is 0.
/// Returns `GpsError::ParseError` if the sentence cannot be parsed.
pub fn parse_gga(sentence: &[u8]) -> Result<GpsPosition, GpsError> {
    validate_checksum(sentence)?;

    // Extract body between $ and *.
    let start = sentence.iter().position(|&b| b == b'$')
        .ok_or(GpsError::ParseError)?;
    let star = sentence.iter().position(|&b| b == b'*')
        .ok_or(GpsError::ParseError)?;
    let body = &sentence[start + 1..star];

    let fields = split_fields(body);
    if fields.len() < 10 {
        return Err(GpsError::ParseError);
    }

    // fields[0] = GPGGA/GNGGA
    // fields[1] = time (hhmmss.ss)
    // fields[2] = lat, fields[3] = N/S
    // fields[4] = lon, fields[5] = E/W
    // fields[6] = fix quality
    // fields[7] = num satellites
    // fields[8] = HDOP
    // fields[9] = altitude, fields[10] = M

    let quality = parse_int(fields[6]).unwrap_or(0) as u8;
    if quality == 0 || fields[2].is_empty() {
        return Err(GpsError::NoFix);
    }

    let latitude = parse_lat(fields[2], fields[3])?;
    let longitude = parse_lon(fields[4], fields[5])?;
    let altitude_mm = parse_altitude_mm(fields[9]).unwrap_or(0);
    let satellite_count = parse_int(fields[7]).unwrap_or(0) as u8;

    Ok(GpsPosition {
        latitude,
        longitude,
        altitude_mm,
        fix_quality: quality,
        satellite_count,
    })
}

/// Parse an RMC sentence (Recommended Minimum Navigation Information).
///
/// Extracts time and date for clock synchronization, plus position.
///
/// # Errors
///
/// Returns `GpsError::ChecksumMismatch` if the checksum is invalid.
/// Returns `GpsError::NoFix` if status is 'V' (void).
/// Returns `GpsError::ParseError` if the sentence cannot be parsed.
pub fn parse_rmc(sentence: &[u8]) -> Result<(GpsPosition, GpsTime), GpsError> {
    validate_checksum(sentence)?;

    let start = sentence.iter().position(|&b| b == b'$')
        .ok_or(GpsError::ParseError)?;
    let star = sentence.iter().position(|&b| b == b'*')
        .ok_or(GpsError::ParseError)?;
    let body = &sentence[start + 1..star];

    let fields = split_fields(body);
    if fields.len() < 10 {
        return Err(GpsError::ParseError);
    }

    // fields[0] = GPRMC/GNRMC
    // fields[1] = time (hhmmss.ss)
    // fields[2] = status (A=active, V=void)
    // fields[3] = lat, fields[4] = N/S
    // fields[5] = lon, fields[6] = E/W
    // fields[7] = speed (knots)
    // fields[8] = course (degrees true)
    // fields[9] = date (ddmmyy)

    if fields[2] != b"A" {
        return Err(GpsError::NoFix);
    }

    let latitude = parse_lat(fields[3], fields[4])?;
    let longitude = parse_lon(fields[5], fields[6])?;

    let position = GpsPosition {
        latitude,
        longitude,
        altitude_mm: 0,
        fix_quality: 1, // GPS fix
        satellite_count: 0,
    };

    let time = parse_time_date(fields[1], fields[9])?;

    Ok((position, time))
}

/// Parse NMEA time (hhmmss.ss) and date (ddmmyy) fields into `GpsTime`.
fn parse_time_date(time_field: &[u8], date_field: &[u8]) -> Result<GpsTime, GpsError> {
    if time_field.len() < 6 || date_field.len() < 6 {
        return Err(GpsError::ParseError);
    }

    let hour = parse_int(&time_field[..2]).ok_or(GpsError::ParseError)? as u8;
    let minute = parse_int(&time_field[2..4]).ok_or(GpsError::ParseError)? as u8;
    let second = parse_int(&time_field[4..6]).ok_or(GpsError::ParseError)? as u8;

    let day = parse_int(&date_field[..2]).ok_or(GpsError::ParseError)? as u8;
    let month = parse_int(&date_field[2..4]).ok_or(GpsError::ParseError)? as u8;
    let year_short = parse_int(&date_field[4..6]).ok_or(GpsError::ParseError)? as u16;
    // NMEA year is two digits; assume 2000+ for years < 70, 1900+ otherwise.
    let year = if year_short < 70 { 2000 + year_short } else { 1900 + year_short };

    Ok(GpsTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

// ---------------------------------------------------------------------------
// Sentence buffer
// ---------------------------------------------------------------------------

/// Accumulates incoming bytes until a complete NMEA sentence (`\r\n`) is found.
pub struct SentenceBuffer {
    /// Internal byte buffer.
    buf: Vec<u8>,
}

impl SentenceBuffer {
    /// Create a new empty sentence buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(SENTENCE_BUF_CAPACITY),
        }
    }

    /// Feed bytes into the buffer.
    pub fn feed(&mut self, data: &[u8]) {
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
    pub fn take_sentence(&mut self) -> Option<Vec<u8>> {
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
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Return true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Hardware abstraction trait
// ---------------------------------------------------------------------------

/// Hardware operations trait for GPS driver abstraction.
///
/// Allows test-friendly mocking of WMT STP transport access.
pub trait GpsHwOps {
    /// Read raw bytes from the GPS data path.
    fn read_data(&mut self, buf: &mut [u8]) -> usize;

    /// Power on the GPS subsystem within the combo chip.
    fn power_on(&mut self) -> Result<(), GpsError>;

    /// Power off the GPS subsystem.
    fn power_off(&mut self) -> Result<(), GpsError>;
}

// ---------------------------------------------------------------------------
// Real hardware implementation (non-test only)
// ---------------------------------------------------------------------------

/// Real GPS hardware access via WMT STP on the MT6739 combo chip.
#[cfg(not(test))]
pub struct GpsHw {
    /// WMT combo-chip MMIO base address.
    consys_base: usize,
}

#[cfg(not(test))]
impl GpsHw {
    /// Create a new GPS hardware handle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            consys_base: MT6739_CONSYS,
        }
    }
}

#[cfg(not(test))]
impl GpsHwOps for GpsHw {
    fn read_data(&mut self, _buf: &mut [u8]) -> usize {
        // TODO(hw): implement WMT STP frame RX for GPS channel.
        0
    }

    fn power_on(&mut self) -> Result<(), GpsError> {
        // TODO(hw): send WMT power-on command for GPS subsystem.
        Ok(())
    }

    fn power_off(&mut self) -> Result<(), GpsError> {
        // TODO(hw): send WMT power-off command for GPS subsystem.
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
pub struct GpsReceiver<H: GpsHwOps> {
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
    pub fn new(hw: H) -> Self {
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
    pub fn state(&self) -> GpsState {
        self.state
    }

    /// Return the most recent position fix, if available.
    #[must_use]
    pub fn position(&self) -> Option<&GpsPosition> {
        self.last_position.as_ref()
    }

    /// Return the most recent GPS time, if available.
    #[must_use]
    pub fn time(&self) -> Option<&GpsTime> {
        self.last_time.as_ref()
    }

    /// Initialize the GPS receiver: power on and begin searching.
    pub fn init(&mut self) -> Result<(), GpsError> {
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
    pub fn poll(&mut self) {
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
    pub fn shutdown(&mut self) -> Result<(), GpsError> {
        self.hw.power_off()?;
        self.state = GpsState::Off;
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
    /// Whether power_on succeeds.
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
        assert_eq!(pos.fix_quality, 1, "fix quality must be 1 (GPS)");
        assert_eq!(pos.satellite_count, 8, "satellite count must be 8");
        // 53 degrees 21.6802 minutes N = ~53361336 microdegrees
        assert!(
            (pos.latitude - 53_361_336).abs() < 100,
            "latitude must be ~53361336 microdegrees, got {}",
            pos.latitude
        );
        // 6 degrees 30.3372 minutes W = ~-6505620 microdegrees (negative for W)
        assert!(
            pos.longitude < 0,
            "longitude must be negative for West"
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

    // -- GGA no-fix error --

    #[test]
    fn parse_gga_returns_error_on_no_fix() {
        let sentence = b"$GPGGA,092750.000,,,,,,0,0,,,,,,,*47";
        let result = parse_gga(sentence);
        assert_eq!(
            result,
            Err(GpsError::NoFix),
            "GGA with fix quality 0 must return NoFix error"
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
        buf.feed(b"$GPGGA,1,2,N,3,E,1,4,1.0,10.0,M,0,M,,*53\r\n$GPRMC,1,A,2,N,3,E,0,0,010170,,,A*00\r\n");

        let first = buf.take_sentence();
        assert!(first.is_some(), "first sentence must be extractable");

        let second = buf.take_sentence();
        assert!(second.is_some(), "second sentence must be extractable");
    }

    // -- Checksum validation --

    #[test]
    fn validate_checksum_rejects_bad_checksum() {
        let sentence = b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*FF";
        assert_eq!(
            validate_checksum(sentence),
            Err(GpsError::ChecksumMismatch),
            "corrupted checksum must be rejected"
        );
    }

    #[test]
    fn validate_checksum_accepts_valid() {
        let sentence = b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76";
        assert!(
            validate_checksum(sentence).is_ok(),
            "valid checksum must be accepted"
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
        assert!(
            receiver.position().is_none(),
            "no position before init"
        );
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

    // -- parse_int --

    #[test]
    fn parse_int_parses_digits() {
        assert_eq!(parse_int(b"123"), Some(123));
        assert_eq!(parse_int(b"0"), Some(0));
        assert_eq!(parse_int(b""), None);
        assert_eq!(parse_int(b"abc"), None);
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
}
