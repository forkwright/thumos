#![no_std]
//! topos-core: the canonical NMEA 0183 checksum, coordinate, and fix-quality
//! semantics (#545).
//!
//! This crate is the single home of the `$...*XX` checksum framing, the
//! ddmm.mmmm coordinate-to-microdegree conversion, the `FixQuality` table,
//! and GGA/RMC sentence parsing. It is shared by the `topos` workspace crate
//! and the thumos kernel (`gps.rs`, the path a real GPS fix actually takes
//! on the device).
//!
//! It exists because the two sides were independent hand-ports and had
//! already diverged (#545):
//!
//! - `topos`'s checksum parser accepted a checksum field with only one hex
//!   digit (`u8::from_str_radix` on the string after `*` does not require a
//!   fixed width), silently validating a truncated sentence whose real
//!   checksum was missing a leading zero. The kernel required exactly two
//!   hex digits.
//! - the kernel widened a parsed GGA fix-quality value to `u8` via a
//!   truncating `as` cast rather than a range check, so a quality field of
//!   `264` wrapped to `8` (a defined, *valid*-looking quality) instead of
//!   being rejected. `topos`'s `u8`-typed parse failed outright on the same
//!   input and fell back to quality `0` (no fix).
//! - the kernel's fixed-point coordinate parser rejected minutes >= 60 and
//!   guarded against an unbounded fractional-digit exponent; `topos`'s
//!   `f64`-based parser did neither, and `f64::parse` on `"5360.0000"`
//!   (60.0, an impossible NMEA value) silently produces a plausible-looking
//!   but wrong coordinate rather than an error.
//! - neither side validated latitude against +/-90 degrees or longitude
//!   against +/-180.
//! - the kernel's altitude parser had no sign handling, so a legitimate
//!   below-sea-level reading (e.g. Death Valley, -86 m) was silently
//!   swallowed by the digit-only integer parser and reported as the
//!   generic malformed-field default; `topos`'s `f64::parse` handled the
//!   sign correctly.
//! - `topos`'s RMC parser never extracted time or date at all, so the
//!   clock-synchronization data the kernel depends on (`clock.rs`'s
//!   highest-trust automatic source) had no workspace-side equivalent to
//!   drift against, and neither implementation bounded the parsed
//!   hour/minute/second/month/day components before treating them as
//!   trustworthy.
//!
//! One parser, one set of bounds, both consumers.
//!
//! `no_std` + alloc so the bare-metal kernel can link it via a path
//! dependency; nothing here performs I/O or decides device policy — a
//! caller is told what a sentence means and chooses what to do about it.

extern crate alloc;

use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A failure parsing an NMEA sentence or its fields.
///
/// Deliberately `Copy` and allocation-free: a hostile or corrupted GPS
/// signal is untrusted input, and the kernel must be able to surface a
/// rejection without a heap allocation on that path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// The sentence does not start with `$`, or has no `*` checksum
    /// delimiter.
    MissingDelimiters,
    /// The two characters after `*` are not both valid hex digits.
    ChecksumNotHex,
    /// The computed checksum did not match the sentence's claimed checksum.
    ChecksumMismatch {
        /// The checksum the sentence claimed.
        expected: u8,
        /// The checksum actually computed over the sentence body.
        actual: u8,
    },
    /// The sentence has fewer fields than its type requires.
    TooFewFields {
        /// Minimum field count required.
        needed: usize,
        /// Field count actually present.
        got: usize,
    },
    /// A coordinate field is shorter than the ddmm.mmmm / dddmm.mmmm
    /// format requires.
    CoordinateTooShort,
    /// A coordinate or numeric field contains a non-digit character where a
    /// digit was required.
    FieldNotDigits,
    /// NMEA minutes must be less than 60; the sentence claimed 60 or more.
    MinutesOutOfRange,
    /// A fractional digit count exceeded the range this parser guards
    /// against (see [`parse_fixed_point`] for why the bound exists).
    FractionalDigitsExceeded,
    /// A magnitude computation overflowed `i64`.
    MagnitudeOverflow,
    /// Decoded latitude fell outside +/-90 degrees.
    LatitudeOutOfBounds,
    /// Decoded longitude fell outside +/-180 degrees.
    LongitudeOutOfBounds,
    /// The sentence is well-formed but carries no fix: GGA quality 0 (or an
    /// undefined/reserved quality code), or RMC status other than `A`.
    NoFix,
    /// A time or date field was too short, contained a non-digit, or a
    /// parsed component was out of range (hour > 23, minute/second > 59,
    /// month outside 1-12, day outside 1-31).
    InvalidTimeDate,
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, CoreError>;

// ---------------------------------------------------------------------------
// Checksum framing
// ---------------------------------------------------------------------------

/// Value of a single ASCII hex digit, or `None` if not a hex digit.
const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Parse exactly two hex character bytes into a `u8`.
const fn parse_hex_byte(hi: u8, lo: u8) -> Option<u8> {
    match (hex_digit(hi), hex_digit(lo)) {
        (Some(h), Some(l)) => Some(h * 16 + l),
        _ => None,
    }
}

/// Compute the NMEA XOR checksum of a sentence body (the bytes between `$`
/// and `*`, exclusive of both).
///
/// Time: O(n) where n is `body.len()` -- a single linear XOR fold over
/// every byte.
/// Space: O(1) -- a single accumulator byte, no allocation.
#[must_use]
pub fn compute_checksum(body: &[u8]) -> u8 {
    body.iter().fold(0u8, |acc, &b| acc ^ b)
}

/// Validate an NMEA sentence's `$...*XX` framing and checksum, and return
/// the body between `$` and `*`.
///
/// Requires `$` at byte 0 (not merely present somewhere in the input --
/// leading garbage before `$` is rejected rather than silently skipped),
/// a non-empty body, and *exactly* two hex-digit checksum characters after
/// `*`. The two-hex-digit requirement is load-bearing: a checksum string
/// parsed with a variable-width hex reader (e.g. `u8::from_str_radix` on a
/// `&str` slice) accepts a single leftover digit as if it were the whole
/// checksum, silently validating a sentence whose checksum lost its leading
/// zero in transit (#545).
///
/// Time: O(n) where n is `sentence.len()` -- scanning for the `*`
/// delimiter and computing the XOR checksum over the body are each a
/// single linear pass.
/// Space: O(1) -- the returned body is a borrowed slice of the input; no
/// bytes are copied.
///
/// # Errors
///
/// - [`CoreError::MissingDelimiters`] when `$` is not at byte 0, there is no
///   `*`, or the body between them is empty.
/// - [`CoreError::ChecksumNotHex`] when the two characters after `*` are not
///   both hex digits (distinct from a checksum that parsed and disagreed).
/// - [`CoreError::ChecksumMismatch`] when the checksum parsed but did not
///   match the computed value.
pub fn checksum_body(sentence: &[u8]) -> Result<&[u8]> {
    if sentence.first() != Some(&b'$') {
        return Err(CoreError::MissingDelimiters);
    }
    let star = sentence
        .iter()
        .position(|&b| b == b'*')
        .ok_or(CoreError::MissingDelimiters)?;
    // INVARIANT: star != 0, because sentence[0] == b'$' (checked above) and
    // '*' cannot equal '$'. `star < 2` therefore means an empty body; the
    // `star + 3 > len` arm means fewer than two characters remain for the
    // checksum -- both are MissingDelimiters, distinct from ChecksumNotHex
    // (two characters present, but not hex).
    if star < 2 || star + 3 > sentence.len() {
        return Err(CoreError::MissingDelimiters);
    }

    // `.get()` rather than direct indexing: both accesses below are always
    // in bounds given the check just above, but bounds-checked access keeps
    // this parser panic-free by construction against untrusted GPS input,
    // not merely by an invariant a future edit could quietly break.
    let body = sentence.get(1..star).ok_or(CoreError::MissingDelimiters)?;
    let expected = sentence
        .get(star + 1)
        .zip(sentence.get(star + 2))
        .and_then(|(&hi, &lo)| parse_hex_byte(hi, lo))
        .ok_or(CoreError::ChecksumNotHex)?;

    let actual = compute_checksum(body);
    if actual == expected {
        Ok(body)
    } else {
        Err(CoreError::ChecksumMismatch { expected, actual })
    }
}

/// Split an NMEA sentence body (already stripped of `$...*XX`) into
/// comma-separated fields.
///
/// Time: O(n) where n is `body.len()` -- a single linear scan, splitting
/// on each comma byte.
/// Space: O(f) where f is the number of fields produced -- each pushed
/// element is a borrowed slice of the input (no byte copies), but the
/// `Vec` of slices itself grows with the field count, which is bounded by
/// n in the worst case of an all-comma body.
///
/// # Panics
///
/// Does not panic: `start` and `i` are always indices produced by
/// enumerating `body` itself, so both remain within `0..=body.len()`.
#[must_use]
pub fn split_fields(body: &[u8]) -> Vec<&[u8]> {
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

// ---------------------------------------------------------------------------
// Numeric primitives
// ---------------------------------------------------------------------------

/// Parse a byte slice of ASCII digits into a `u32`.
///
/// Time: O(n) where n is `bytes.len()` -- a single linear scan; exits
/// early only on a non-digit byte or on `u32` overflow.
/// Space: O(1) -- a single `u32` accumulator, no allocation.
#[must_use]
pub fn parse_uint(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut result: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }
    Some(result)
}

/// Parse a byte slice of ASCII digits into a `u8`, defaulting to 0 when the
/// field is malformed or out of `u8` range.
///
/// WHY a saturate-to-default rather than a truncating cast: a quality or
/// satellite-count field of `264` truncated via `as u8` wraps to `8` -- a
/// *valid-looking* code -- instead of the parse simply failing. Truncation
/// turns a malformed field into a specific, wrong, but plausible value;
/// defaulting to 0 keeps the failure visible as "unknown" (#545).
#[must_use]
pub fn parse_uint_u8_or_zero(bytes: &[u8]) -> u8 {
    parse_uint(bytes)
        .and_then(|v| u8::try_from(v).ok())
        .unwrap_or(0)
}

/// Parse a decimal fraction's digits, scaled to `scale` decimal places.
///
/// `frac_bytes` holds only the digits after a decimal point (no sign, no
/// leading `.`). Returns `0` for an empty slice.
fn scaled_fraction(frac_bytes: &[u8], scale: u32) -> Result<i64> {
    if frac_bytes.is_empty() {
        return Ok(0);
    }
    let raw = i64::from(parse_uint(frac_bytes).ok_or(CoreError::FieldNotDigits)?);
    // WHY: an adversarial source controls the fractional digit count; past
    // ~18 digits, `10i64.pow(frac_len - scale)` below overflows i64 and (in
    // a release build with overflow-checks off) silently wraps rather than
    // panicking, corrupting the parsed magnitude instead of erroring. Bound
    // it well under i64's ~19-digit decimal range. Applies uniformly to
    // coordinate minutes and to altitude, which previously guarded this
    // only on the coordinate path (#545).
    let frac_len = frac_bytes.len();
    if frac_len > 18 {
        return Err(CoreError::FractionalDigitsExceeded);
    }
    // INVARIANT: frac_len <= 18, so the u32 conversion below never truncates.
    let frac_len = frac_len as u32;
    Ok(match frac_len.cmp(&scale) {
        core::cmp::Ordering::Less => raw.saturating_mul(10i64.pow(scale - frac_len)),
        core::cmp::Ordering::Greater => raw / 10i64.pow(frac_len - scale),
        core::cmp::Ordering::Equal => raw,
    })
}

/// Parse a signed fixed-point decimal (e.g. altitude in meters) into an
/// integer scaled by `10^scale` (e.g. `scale = 3` for millimeters from
/// meters).
///
/// Handles an optional leading `-` -- a below-sea-level altitude (e.g.
/// Death Valley, -86 m) is a legitimate NMEA value, not a malformed one.
///
/// Time: O(n) where n is `bytes.len()` -- one linear scan to locate the
/// decimal point, plus parsing the integer and fractional digit runs (each
/// via `parse_uint`), together a single pass over the input. Note the
/// fractional-digit-count guard (`FractionalDigitsExceeded`) is checked
/// only AFTER `parse_uint` has already scanned the full fractional part,
/// so it bounds the magnitude computation, not this function's cost --
/// an adversarial all-digit fractional field is scanned in full regardless
/// of length.
/// Space: O(1) -- all slicing is by reference; no allocation.
///
/// # Errors
///
/// [`CoreError::FieldNotDigits`] when the integer or fractional part is not
/// all ASCII digits. [`CoreError::FractionalDigitsExceeded`] when the
/// fractional part is implausibly long (the internal `scaled_fraction`
/// helper bounds it to 18 digits). [`CoreError::MagnitudeOverflow`] on
/// integer overflow assembling the scaled value.
///
/// # Panics
///
/// Does not panic: `pos` is produced by `bytes.iter().position(...)`, so
/// it is always a valid split point within `bytes`.
pub fn parse_fixed_point(bytes: &[u8], scale: u32) -> Result<i64> {
    let (negative, bytes) = match bytes.first() {
        Some(b'-') => (true, bytes.get(1..).unwrap_or(&[])),
        _ => (false, bytes),
    };
    if bytes.is_empty() {
        return Err(CoreError::FieldNotDigits);
    }
    let dot_pos = bytes.iter().position(|&b| b == b'.');
    let (int_bytes, frac_bytes) = dot_pos.map_or((bytes, &[] as &[u8]), |pos| {
        (&bytes[..pos], &bytes[pos + 1..])
    });

    let int_val = i64::from(parse_uint(int_bytes).ok_or(CoreError::FieldNotDigits)?);
    let frac_scaled = scaled_fraction(frac_bytes, scale)?;
    let scale_factor = 10i64
        .checked_pow(scale)
        .ok_or(CoreError::MagnitudeOverflow)?;
    let magnitude = int_val
        .checked_mul(scale_factor)
        .and_then(|v| v.checked_add(frac_scaled))
        .ok_or(CoreError::MagnitudeOverflow)?;

    Ok(if negative { -magnitude } else { magnitude })
}

/// Parse an altitude field (meters, optionally signed, optional decimal)
/// into millimeters.
///
/// Returns `None` -- rather than an error -- when the field is empty or
/// malformed: a bad altitude reading does not invalidate the rest of a fix
/// on either consumer. Distinct from `Some(0)`, which is an actual
/// sea-level reading.
#[must_use]
pub fn parse_altitude_mm(bytes: &[u8]) -> Option<i32> {
    if bytes.is_empty() {
        return None;
    }
    let val = parse_fixed_point(bytes, 3).ok()?;
    i32::try_from(val).ok()
}

// ---------------------------------------------------------------------------
// Coordinates
// ---------------------------------------------------------------------------

/// Scale factor between decimal degrees and microdegrees.
pub const MICRODEG_SCALE: i64 = 1_000_000;

/// Maximum valid absolute latitude, in microdegrees.
pub const MAX_LATITUDE_UDEG: i64 = 90 * MICRODEG_SCALE;

/// Maximum valid absolute longitude, in microdegrees.
pub const MAX_LONGITUDE_UDEG: i64 = 180 * MICRODEG_SCALE;

/// A geographic position in fixed-point microdegrees (degrees *
/// `1_000_000`), avoiding floating-point arithmetic so the value is usable
/// from a `no_std` kernel without FPU support enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Position {
    /// Latitude in microdegrees. Positive = North, negative = South.
    pub lat_udeg: i64,
    /// Longitude in microdegrees. Positive = East, negative = West.
    pub lon_udeg: i64,
}

/// Parse an NMEA `ddmm.mmmm`-shaped coordinate magnitude (no sign) into
/// microdegrees. `deg_digits` is 2 for latitude, 3 for longitude.
fn parse_coordinate_magnitude(value: &[u8], deg_digits: usize) -> Result<i64> {
    if value.len() < deg_digits + 2 {
        return Err(CoreError::CoordinateTooShort);
    }
    let degrees = i64::from(parse_uint(&value[..deg_digits]).ok_or(CoreError::FieldNotDigits)?);
    let minutes_part = &value[deg_digits..];

    let dot_pos = minutes_part.iter().position(|&b| b == b'.');
    let (int_part, frac_part) = dot_pos.map_or((minutes_part, &[] as &[u8]), |pos| {
        (&minutes_part[..pos], &minutes_part[pos + 1..])
    });

    let minutes_int = i64::from(parse_uint(int_part).ok_or(CoreError::FieldNotDigits)?);
    // Minutes scaled to 4 decimal places (1/10000ths).
    let frac_val = scaled_fraction(frac_part, 4)?;
    let minutes_scaled = minutes_int * 10_000 + frac_val;

    // INVARIANT: NMEA minutes must be in [0, 60); minutes_scaled is minutes
    // in units of 1/10000, so the bound is 60 * 10000 = 600_000. A source
    // reporting >= 60 minutes is malformed and must not silently wrap into
    // the next degree (#545: the f64-based parser this replaces on the
    // `topos` side had no such check -- "5360.0000" parsed as 60.0 minutes
    // and silently produced a wrong-but-plausible coordinate).
    if minutes_scaled >= 600_000 {
        return Err(CoreError::MinutesOutOfRange);
    }

    Ok(degrees * MICRODEG_SCALE + minutes_scaled * MICRODEG_SCALE / 600_000)
}

/// Parse an NMEA latitude field (`ddmm.mmmm`) and hemisphere (`N`/`S`) into
/// signed microdegrees, bounded to +/-90 degrees.
///
/// # Errors
///
/// [`CoreError::CoordinateTooShort`] / [`CoreError::FieldNotDigits`] /
/// [`CoreError::MinutesOutOfRange`] / [`CoreError::FractionalDigitsExceeded`]
/// from the underlying coordinate parse, plus
/// [`CoreError::LatitudeOutOfBounds`] when the magnitude exceeds 90 degrees.
pub fn parse_lat(value: &[u8], hemisphere: &[u8]) -> Result<i64> {
    let magnitude = parse_coordinate_magnitude(value, 2)?;
    let signed = if hemisphere == b"S" {
        -magnitude
    } else {
        magnitude
    };
    if !(-MAX_LATITUDE_UDEG..=MAX_LATITUDE_UDEG).contains(&signed) {
        return Err(CoreError::LatitudeOutOfBounds);
    }
    Ok(signed)
}

/// Parse an NMEA longitude field (`dddmm.mmmm`) and hemisphere (`E`/`W`)
/// into signed microdegrees, bounded to +/-180 degrees.
///
/// # Errors
///
/// As [`parse_lat`], plus [`CoreError::LongitudeOutOfBounds`] when the
/// magnitude exceeds 180 degrees.
pub fn parse_lon(value: &[u8], hemisphere: &[u8]) -> Result<i64> {
    let magnitude = parse_coordinate_magnitude(value, 3)?;
    let signed = if hemisphere == b"W" {
        -magnitude
    } else {
        magnitude
    };
    if !(-MAX_LONGITUDE_UDEG..=MAX_LONGITUDE_UDEG).contains(&signed) {
        return Err(CoreError::LongitudeOutOfBounds);
    }
    Ok(signed)
}

// ---------------------------------------------------------------------------
// Fix quality
// ---------------------------------------------------------------------------

/// GPS fix quality indicator (NMEA GGA field 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FixQuality {
    /// No fix, or a quality code outside the defined 1-8 range.
    ///
    /// WHY undefined codes fold into `NoFix` rather than being passed
    /// through: a reserved/future quality code is not a stronger fix than
    /// none, and treating any nonzero byte as "has a fix" (a truncating
    /// `u8` cast previously did exactly that for field text like `264`,
    /// #545) is fail-open on the one field that gates whether a position is
    /// trusted at all.
    #[default]
    NoFix,
    /// Standard GPS fix.
    Gps,
    /// Differential GPS fix.
    Dgps,
    /// PPS fix.
    Pps,
    /// Real-Time Kinematic.
    Rtk,
    /// Float RTK.
    FloatRtk,
    /// Estimated (dead reckoning).
    Estimated,
    /// Manual input mode.
    Manual,
    /// Simulation mode.
    Simulation,
}

impl FixQuality {
    /// Whether this quality indicates a usable fix.
    #[must_use]
    pub const fn has_fix(self) -> bool {
        !matches!(self, Self::NoFix)
    }
}

impl From<u8> for FixQuality {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::Gps,
            2 => Self::Dgps,
            3 => Self::Pps,
            4 => Self::Rtk,
            5 => Self::FloatRtk,
            6 => Self::Estimated,
            7 => Self::Manual,
            8 => Self::Simulation,
            _ => Self::NoFix,
        }
    }
}

// ---------------------------------------------------------------------------
// Fix (GGA / RMC)
// ---------------------------------------------------------------------------

/// A GPS fix as extracted from a GGA or RMC sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fix {
    /// Geographic position.
    pub position: Position,
    /// Fix quality.
    pub quality: FixQuality,
    /// Number of satellites in use. `0` when absent or malformed (GGA
    /// only; RMC carries no satellite count).
    pub satellite_count: u8,
    /// Altitude above mean sea level in millimeters. `None` when the
    /// sentence omitted the field or it did not parse -- distinct from an
    /// actual sea-level (`Some(0)`) reading. GGA only; RMC carries no
    /// altitude.
    pub altitude_mm: Option<i32>,
}

/// Parse a GGA sentence (Global Positioning System Fix Data).
///
/// Format: `$GPGGA,hhmmss.ss,llll.ll,a,yyyyy.yy,a,q,ss,h.h,a.a,M,g.g,M,,*hh`
///
/// # Errors
///
/// [`CoreError::ChecksumMismatch`] / [`CoreError::MissingDelimiters`] /
/// [`CoreError::ChecksumNotHex`] on framing failures.
/// [`CoreError::TooFewFields`] when the body has fewer than 10 fields.
/// [`CoreError::NoFix`] when quality is 0 (or undefined) or the latitude
/// field is empty. [`CoreError::LatitudeOutOfBounds`] /
/// [`CoreError::LongitudeOutOfBounds`] / coordinate errors from malformed
/// position fields.
///
/// # Panics
///
/// Does not panic: every `fields[N]` access below indexes N < 10, and the
/// `fields.len() < 10` check just above guarantees at least 10 elements.
pub fn parse_gga(sentence: &[u8]) -> Result<Fix> {
    let body = checksum_body(sentence)?;
    let fields = split_fields(body);
    if fields.len() < 10 {
        return Err(CoreError::TooFewFields {
            needed: 10,
            got: fields.len(),
        });
    }

    // fields[0] = GPGGA/GNGGA   fields[1] = time
    // fields[2] = lat           fields[3] = N/S
    // fields[4] = lon           fields[5] = E/W
    // fields[6] = fix quality   fields[7] = num satellites
    // fields[8] = HDOP          fields[9] = altitude

    let quality = FixQuality::from(parse_uint_u8_or_zero(fields[6]));
    if !quality.has_fix() || fields[2].is_empty() {
        return Err(CoreError::NoFix);
    }

    let position = Position {
        lat_udeg: parse_lat(fields[2], fields[3])?,
        lon_udeg: parse_lon(fields[4], fields[5])?,
    };
    let altitude_mm = parse_altitude_mm(fields[9]);
    let satellite_count = parse_uint_u8_or_zero(fields[7]);

    Ok(Fix {
        position,
        quality,
        satellite_count,
        altitude_mm,
    })
}

/// UTC date and time extracted from an RMC sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    /// Year (full, e.g. 2026).
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

/// Parse NMEA time (`hhmmss.ss`) and date (`ddmmyy`) fields into a
/// [`DateTime`], with range validation on every component.
///
/// WHY the range check exists even though neither prior implementation had
/// it: consumers may treat GPS-derived time as their highest-trust
/// automatic clock source, and the checksum only proves the sentence text
/// is internally consistent -- not that the values are truthful. A spoofed
/// or corrupted signal can carry an in-checksum sentence with an
/// impossible hour or month; a consumer that feeds that straight into a
/// trusted clock hierarchy without validating the ranges has a fail-open
/// gap on the exact axis "highest trust" is supposed to mean (#545).
///
/// # Errors
///
/// [`CoreError::InvalidTimeDate`] when either field is too short, contains
/// a non-digit, or a parsed component is out of range.
///
/// # Panics
///
/// Does not panic: every range slice below stays within the first 6 bytes
/// of its field, and the length check just above guarantees at least 6.
pub fn parse_time_date(time_field: &[u8], date_field: &[u8]) -> Result<DateTime> {
    if time_field.len() < 6 || date_field.len() < 6 {
        return Err(CoreError::InvalidTimeDate);
    }

    let hour = parse_uint(&time_field[..2]).ok_or(CoreError::InvalidTimeDate)?;
    let minute = parse_uint(&time_field[2..4]).ok_or(CoreError::InvalidTimeDate)?;
    let second = parse_uint(&time_field[4..6]).ok_or(CoreError::InvalidTimeDate)?;
    let day = parse_uint(&date_field[..2]).ok_or(CoreError::InvalidTimeDate)?;
    let month = parse_uint(&date_field[2..4]).ok_or(CoreError::InvalidTimeDate)?;
    let year_short = parse_uint(&date_field[4..6]).ok_or(CoreError::InvalidTimeDate)?;

    if hour > 23
        || minute > 59
        || second > 59
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return Err(CoreError::InvalidTimeDate);
    }

    // NMEA's two-digit year maps to 1900+year for year_short >= 70,
    // 2000+year otherwise.
    let year = if year_short < 70 {
        2000 + year_short
    } else {
        1900 + year_short
    };

    // INVARIANT: hour/minute/second <= 59, month <= 12, day <= 31, and year
    // <= 2069 -- all well within their target integer widths, checked above.
    Ok(DateTime {
        year: year as u16,
        month: month as u8,
        day: day as u8,
        hour: hour as u8,
        minute: minute as u8,
        second: second as u8,
    })
}

/// Parse an RMC sentence (Recommended Minimum Navigation Information).
///
/// Format: `$GPRMC,hhmmss.ss,A,llll.ll,a,yyyyy.yy,a,s.s,c.c,ddmmyy,,,a*hh`
///
/// Returns a [`Fix`] with `quality = FixQuality::Gps`, `satellite_count = 0`,
/// and `altitude_mm = None` -- RMC carries neither. Speed and course are
/// plain informational floats with no NMEA-specific semantics beyond
/// `str::parse`; callers that want them read `fields[7]`/`fields[8]`
/// themselves via [`checksum_body`] + [`split_fields`].
///
/// # Errors
///
/// As [`parse_gga`], plus [`CoreError::NoFix`] when the status field is not
/// `A` (active). [`CoreError::InvalidTimeDate`] from [`parse_time_date`].
///
/// # Panics
///
/// Does not panic: every `fields[N]` access below indexes N < 10, and the
/// `fields.len() < 10` check just above guarantees at least 10 elements.
pub fn parse_rmc(sentence: &[u8]) -> Result<(Fix, DateTime)> {
    let body = checksum_body(sentence)?;
    let fields = split_fields(body);
    if fields.len() < 10 {
        return Err(CoreError::TooFewFields {
            needed: 10,
            got: fields.len(),
        });
    }

    // fields[0] = GPRMC/GNRMC   fields[1] = time
    // fields[2] = status (A/V) fields[3] = lat   fields[4] = N/S
    // fields[5] = lon          fields[6] = E/W
    // fields[7] = speed(kn)    fields[8] = course   fields[9] = date

    if fields[2] != b"A" {
        return Err(CoreError::NoFix);
    }

    let position = Position {
        lat_udeg: parse_lat(fields[3], fields[4])?,
        lon_udeg: parse_lon(fields[5], fields[6])?,
    };
    let fix = Fix {
        position,
        quality: FixQuality::Gps,
        satellite_count: 0,
        altitude_mm: None,
    };
    let time = parse_time_date(fields[1], fields[9])?;

    Ok((fix, time))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok<T>(r: Result<T>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => unreachable!("expected Ok, got {e:?}"),
        }
    }

    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    /// Build a valid-checksum NMEA sentence "$<body>*<XX>" for tests that
    /// need to get past `checksum_body` before reaching a deeper branch.
    fn nmea_sentence(body: &[u8]) -> alloc::vec::Vec<u8> {
        let checksum = compute_checksum(body);
        let mut sentence = alloc::vec::Vec::new();
        sentence.push(b'$');
        sentence.extend_from_slice(body);
        sentence.push(b'*');
        sentence.push(HEX[usize::from(checksum >> 4)]);
        sentence.push(HEX[usize::from(checksum & 0xF)]);
        sentence
    }

    // -- checksum framing --

    #[test]
    fn checksum_body_accepts_valid_sentence() {
        let sentence = b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76";
        assert!(
            checksum_body(sentence).is_ok(),
            "a valid checksum must be accepted"
        );
    }

    #[test]
    fn checksum_body_rejects_bad_checksum() {
        let sentence = b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*FF";
        assert_eq!(
            checksum_body(sentence),
            Err(CoreError::ChecksumMismatch {
                expected: 0xFF,
                actual: 0x76
            }),
            "a corrupted checksum byte must be rejected with the mismatched values"
        );
    }

    #[test]
    fn checksum_body_rejects_non_hex_digits_as_distinct_from_mismatch() {
        let sentence = b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*ZZ";
        assert_eq!(
            checksum_body(sentence),
            Err(CoreError::ChecksumNotHex),
            "non-hex checksum characters are a distinct failure from a hex checksum that disagreed"
        );
    }

    #[test]
    fn checksum_body_rejects_a_truncated_single_digit_checksum() {
        // #545: "$00*0" -- body "00" (XOR checksum 0x00), followed by a
        // checksum field with only ONE hex character. A width-flexible hex
        // parser (`u8::from_str_radix` on the trailing string, which is
        // what `topos`'s original parser used) reads "0" as 0x00 and
        // validates it, silently accepting a sentence whose checksum lost
        // its leading zero. Exactly two hex digits must be required.
        let sentence = b"$00*0";
        assert_eq!(
            checksum_body(sentence),
            Err(CoreError::MissingDelimiters),
            "a checksum field with only one hex digit must be rejected, not \
             read as a valid one-digit checksum"
        );
    }

    #[test]
    fn checksum_body_requires_dollar_at_byte_zero() {
        // Leading bytes before `$` must not be silently skipped -- their
        // presence means the "sentence" was not cleanly framed.
        let sentence = b"XX$GPGGA,1,2*00";
        assert_eq!(
            checksum_body(sentence),
            Err(CoreError::MissingDelimiters),
            "a sentence must start with $ at byte 0, not merely contain one"
        );
    }

    #[test]
    fn checksum_body_rejects_empty_body() {
        let sentence = b"$*76";
        assert_eq!(
            checksum_body(sentence),
            Err(CoreError::MissingDelimiters),
            "an empty body between $ and * must be rejected"
        );
    }

    // -- fix quality: truncating-cast divergence --

    #[test]
    fn quality_264_is_rejected_not_wrapped_to_a_valid_code() {
        // #545: the kernel's original `parse_int(...).unwrap_or(0) as u8`
        // wrapped 264 -> 8 (Simulation, a DEFINED quality) via truncation.
        // `topos`'s `str::parse::<u8>()` failed outright on "264" and fell
        // back to 0. Neither wrapping-to-a-valid-code nor "reject the
        // sentence outright" is quite right for a field this permissive
        // elsewhere -- the converged behavior treats a field this
        // malformed as if it were absent (0 -> NoFix), matching `topos`'s
        // fail-closed direction without hard-failing the whole sentence.
        assert_eq!(
            parse_uint_u8_or_zero(b"264"),
            0,
            "a quality value that overflows u8 must default to 0, not wrap"
        );
        assert_eq!(
            FixQuality::from(parse_uint_u8_or_zero(b"264")),
            FixQuality::NoFix,
            "an overflowing quality field must never resolve to a defined \
             (accepted) quality code"
        );
    }

    #[test]
    fn quality_9_undefined_code_is_no_fix() {
        // Values 9+ are reserved/undefined by NMEA 0183. The kernel's
        // original check was `quality == 0`, which let ANY nonzero byte
        // (including 9, 50, 200) through as "has a fix". `topos` already
        // rejected undefined codes via `FixQuality::from`; this converges
        // the kernel onto that stricter behavior.
        assert_eq!(
            FixQuality::from(9),
            FixQuality::NoFix,
            "an undefined quality code must not be treated as a valid fix"
        );
        assert!(!FixQuality::from(9).has_fix());
    }

    #[test]
    fn quality_1_through_8_are_defined_fixes() {
        for q in 1u8..=8 {
            assert!(
                FixQuality::from(q).has_fix(),
                "quality code {q} is defined by NMEA 0183 and must report has_fix()"
            );
        }
    }

    // -- coordinate bounds --

    #[test]
    fn parse_lat_rejects_minutes_of_60_or_more() {
        // "5360.0000" is 53 degrees, 60.0 minutes -- impossible NMEA. The
        // f64 parser `topos` used before convergence had no such check and
        // would have silently computed 53 + 60.0/60.0 = 54.0 degrees, a
        // plausible-looking but wrong coordinate.
        assert_eq!(
            parse_lat(b"5360.0000", b"N"),
            Err(CoreError::MinutesOutOfRange),
            "minutes >= 60 must be rejected, not silently carried into the next degree"
        );
    }

    #[test]
    fn parse_lat_accepts_minutes_just_under_60() {
        assert!(
            parse_lat(b"5359.9999", b"N").is_ok(),
            "minutes just under 60 must be accepted"
        );
    }

    #[test]
    fn parse_lat_rejects_out_of_bounds_latitude() {
        // 95 degrees north does not exist. Neither implementation checked
        // this before convergence.
        assert_eq!(
            parse_lat(b"9500.0000", b"N"),
            Err(CoreError::LatitudeOutOfBounds),
            "a latitude magnitude exceeding 90 degrees must be rejected"
        );
    }

    #[test]
    fn parse_lat_accepts_exactly_90_degrees() {
        assert!(
            parse_lat(b"9000.0000", b"N").is_ok(),
            "exactly 90 degrees (the pole) is a valid boundary value"
        );
    }

    #[test]
    fn parse_lon_rejects_out_of_bounds_longitude() {
        assert_eq!(
            parse_lon(b"20000.0000", b"E"),
            Err(CoreError::LongitudeOutOfBounds),
            "a longitude magnitude exceeding 180 degrees must be rejected"
        );
    }

    #[test]
    fn parse_lat_rejects_excessive_fractional_digit_count() {
        let value = b"5321.00000000000000000000000"; // 23 fractional digits
        assert_eq!(
            parse_lat(value, b"N"),
            Err(CoreError::FractionalDigitsExceeded),
            "23+ fractional digits must error instead of overflowing 10i64.pow"
        );
    }

    #[test]
    fn parse_lat_converts_hemisphere_sign() {
        let north = ok(parse_lat(b"3348.5410", b"N"));
        let south = ok(parse_lat(b"3348.5410", b"S"));
        assert!(north > 0, "N must be positive");
        assert_eq!(south, -north, "S must be the exact negation of N");
    }

    // -- altitude: sign handling --

    #[test]
    fn parse_altitude_mm_handles_negative_altitude() {
        // Death Valley is about -86 m. The kernel's original digit-only
        // integer parser had no sign handling and silently fell through to
        // the generic malformed-field default; `topos`'s f64 parser
        // handled the sign correctly.
        assert_eq!(
            parse_altitude_mm(b"-86.0"),
            Some(-86_000),
            "a negative altitude must parse to a negative millimeter value, \
             not fall back to the malformed-field default"
        );
    }

    #[test]
    fn parse_altitude_mm_positive_and_absent() {
        assert_eq!(parse_altitude_mm(b"61.7"), Some(61_700));
        assert_eq!(
            parse_altitude_mm(b""),
            None,
            "an empty altitude field must be None (unknown), not Some(0)"
        );
    }

    #[test]
    fn parse_fixed_point_rejects_excessive_fractional_digits() {
        // The same unbounded-exponent guard applied to coordinates must
        // also apply here -- it previously did not (#545): the kernel's
        // altitude parser had no equivalent bound.
        let garbage = b"1.000000000000000000000"; // > 18 fractional digits
        assert_eq!(
            parse_fixed_point(garbage, 3),
            Err(CoreError::FractionalDigitsExceeded),
            "an implausibly long fractional part must error, not risk an \
             overflowing pow() in the scale computation"
        );
    }

    // -- GGA --

    #[test]
    fn parse_gga_extracts_position_quality_and_satellites() {
        let sentence = b"$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76";
        let fix = ok(parse_gga(sentence));
        assert_eq!(
            fix.quality,
            FixQuality::Gps,
            "fix quality must be GPS for quality indicator 1"
        );
        assert_eq!(fix.satellite_count, 8, "satellite count must match field 7");
        assert!(
            (fix.position.lat_udeg - 53_361_336).abs() < 100,
            "latitude must be ~53361336 microdegrees, got {}",
            fix.position.lat_udeg
        );
        assert!(
            fix.position.lon_udeg < 0,
            "longitude must be negative for West"
        );
        assert_eq!(
            fix.altitude_mm,
            Some(61_700),
            "altitude must parse to 61700 mm"
        );
    }

    #[test]
    fn parse_gga_returns_no_fix_on_quality_zero() {
        let sentence = nmea_sentence(b"GPGGA,092750.000,,,,,,0,0,,,,,,,");
        assert_eq!(
            parse_gga(&sentence),
            Err(CoreError::NoFix),
            "GGA with fix quality 0 must return NoFix"
        );
    }

    #[test]
    fn parse_gga_rejects_fewer_than_ten_fields() {
        let sentence = nmea_sentence(b"GPGGA,1,2,3");
        assert_eq!(
            parse_gga(&sentence),
            Err(CoreError::TooFewFields { needed: 10, got: 4 }),
            "a GGA sentence with fewer than 10 fields must be rejected"
        );
    }

    // -- RMC --

    #[test]
    fn parse_rmc_extracts_position_and_time() {
        let sentence = b"$GPRMC,092750.000,A,5321.6802,N,00630.3372,W,0.02,31.66,280511,,,A*43";
        let (fix, time) = ok(parse_rmc(sentence));
        assert_eq!(fix.quality, FixQuality::Gps);
        assert_eq!(
            time,
            DateTime {
                year: 2011,
                month: 5,
                day: 28,
                hour: 9,
                minute: 27,
                second: 50,
            },
            "RMC time/date fields must be extracted -- a capability the \
             workspace side never had before convergence (#545)"
        );
    }

    #[test]
    fn parse_rmc_void_status_returns_no_fix() {
        let sentence =
            nmea_sentence(b"GPRMC,092750.000,V,5321.6802,N,00630.3372,W,0.02,31.66,280511,,,A");
        assert_eq!(
            parse_rmc(&sentence),
            Err(CoreError::NoFix),
            "RMC status 'V' (void) must return NoFix even though every \
             other field is well-formed"
        );
    }

    #[test]
    fn parse_rmc_rejects_fewer_than_ten_fields() {
        let sentence = nmea_sentence(b"GPRMC,1,A,2");
        assert_eq!(
            parse_rmc(&sentence),
            Err(CoreError::TooFewFields { needed: 10, got: 4 }),
        );
    }

    // -- time/date bounds --

    #[test]
    fn parse_time_date_rejects_impossible_hour() {
        // Neither implementation validated this before convergence.
        // clock.rs treats GPS as its highest-trust automatic clock source.
        assert_eq!(
            parse_time_date(b"992750", b"280511"),
            Err(CoreError::InvalidTimeDate),
            "an hour of 99 must be rejected before it can reach a trusted clock"
        );
    }

    #[test]
    fn parse_time_date_rejects_impossible_month() {
        assert_eq!(
            parse_time_date(b"092750", b"289911"),
            Err(CoreError::InvalidTimeDate),
            "a month of 99 must be rejected"
        );
    }

    #[test]
    fn parse_time_date_applies_1900_century_for_year_70_and_above() {
        let dt = ok(parse_time_date(b"092750", b"280599"));
        assert_eq!(
            dt,
            DateTime {
                year: 1999,
                month: 5,
                day: 28,
                hour: 9,
                minute: 27,
                second: 50,
            },
            "year_short=99 must map to 1999, not 2099"
        );
    }
}
