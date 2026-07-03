//! NMEA 0183 sentence parser.
//!
//! Parses standard GPS sentences: GGA (fix data), RMC (recommended minimum),
//! GSA (DOP and active satellites), GSV (satellites in view).

use crate::error::{self, Error};
use crate::position::{Fix, FixQuality, Position};

/// Validate NMEA checksum and return the sentence body (between '$' and '*').
///
/// Callers can use the returned `&str` to avoid re-parsing the sentence boundary.
pub(crate) fn validate_checksum(sentence: &str) -> Result<&str, Error> {
    let inner = sentence
        .strip_prefix('$')
        .and_then(|s| s.split('*').next())
        .ok_or_else(|| Error::Parse {
            message: "missing $ prefix or * checksum delimiter".to_owned(),
        })?;

    let expected_str = sentence
        .split('*')
        .nth(1)
        .map(str::trim)
        .ok_or_else(|| Error::Parse {
            message: "missing checksum after *".to_owned(),
        })?;

    let expected = u8::from_str_radix(expected_str, 16).map_err(|_| Error::Parse {
        message: format!("invalid checksum hex: {expected_str}"),
    })?;

    let actual = inner.bytes().fold(0u8, |acc, b| acc ^ b);

    if actual == expected {
        Ok(inner)
    } else {
        Err(Error::ChecksumMismatch { expected, actual })
    }
}

/// Compute NMEA checksum for a sentence body (without $ and *).
pub(crate) fn compute_checksum(body: &str) -> u8 {
    body.bytes().fold(0u8, |acc, b| acc ^ b)
}

/// Parse a GGA sentence (Global Positioning System Fix Data).
///
/// Format: `$GPGGA,hhmmss.ss,llll.ll,a,yyyyy.yy,a,x,xx,x.x,x.x,M,x.x,M,x.x,xxxx*hh`
pub(crate) fn parse_gga(sentence: &str) -> error::Result<Fix> {
    validate_checksum(sentence)?;

    let body = sentence
        .strip_prefix('$')
        .and_then(|s| s.split('*').next())
        .ok_or_else(|| Error::Parse {
            message: "invalid GGA sentence".to_owned(),
        })?;

    let fields: Vec<&str> = body.split(',').collect();
    if fields.len() < 10 {
        return Err(Error::Parse {
            message: format!("GGA needs 10+ fields, got {}", fields.len()),
        });
    }

    // fields[0] = GPGGA/GNGGA
    // fields[1] = time (hhmmss.ss)
    // fields[2] = lat, fields[3] = N/S
    // fields[4] = lon, fields[5] = E/W
    // fields[6] = fix quality
    // fields[7] = num satellites
    // fields[8] = HDOP
    // fields[9] = altitude, fields[10] = M

    let quality_val: u8 = fields
        .get(6)
        .copied()
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    let quality = FixQuality::from(quality_val);

    if quality == FixQuality::NoFix || fields.get(2).copied().unwrap_or_default().is_empty() {
        return Err(Error::NoFix);
    }

    let lat = parse_lat_field(
        fields.get(2).copied().unwrap_or_default(),
        fields.get(3).copied().unwrap_or_default(),
    )?;
    let lon = parse_lon_field(
        fields.get(4).copied().unwrap_or_default(),
        fields.get(5).copied().unwrap_or_default(),
    )?;
    let alt = fields.get(9).and_then(|s| s.parse::<f64>().ok());
    let satellites: u8 = fields
        .get(7)
        .copied()
        .unwrap_or_default()
        .parse()
        .unwrap_or(0);
    let hdop = fields.get(8).and_then(|s| s.parse::<f64>().ok());

    Ok(Fix {
        position: Position { lat, lon, alt },
        quality,
        satellites,
        hdop,
        speed_knots: None,
        course: None,
    })
}

/// Parse a RMC sentence (Recommended Minimum Navigation Information).
///
/// Format: `$GPRMC,hhmmss.ss,A,llll.ll,a,yyyyy.yy,a,x.x,x.x,ddmmyy,x.x,a*hh`
pub(crate) fn parse_rmc(sentence: &str) -> error::Result<Fix> {
    validate_checksum(sentence)?;

    let body = sentence
        .strip_prefix('$')
        .and_then(|s| s.split('*').next())
        .ok_or_else(|| Error::Parse {
            message: "invalid RMC sentence".to_owned(),
        })?;

    let fields: Vec<&str> = body.split(',').collect();
    if fields.len() < 10 {
        return Err(Error::Parse {
            message: format!("RMC needs 10+ fields, got {}", fields.len()),
        });
    }

    // fields[0] = GPRMC/GNRMC
    // fields[1] = time
    // fields[2] = status (A=active, V=void)
    // fields[3] = lat, fields[4] = N/S
    // fields[5] = lon, fields[6] = E/W
    // fields[7] = speed (knots)
    // fields[8] = course (degrees true)
    // fields[9] = date (ddmmyy)

    if fields.get(2).copied().unwrap_or_default() != "A" {
        return Err(Error::NoFix);
    }

    let lat = parse_lat_field(
        fields.get(3).copied().unwrap_or_default(),
        fields.get(4).copied().unwrap_or_default(),
    )?;
    let lon = parse_lon_field(
        fields.get(5).copied().unwrap_or_default(),
        fields.get(6).copied().unwrap_or_default(),
    )?;
    let speed_knots = fields.get(7).and_then(|s| s.parse::<f64>().ok());
    let course = fields.get(8).and_then(|s| s.parse::<f64>().ok());

    Ok(Fix {
        position: Position {
            lat,
            lon,
            alt: None,
        },
        quality: FixQuality::Gps,
        satellites: 0,
        hdop: None,
        speed_knots,
        course,
    })
}

/// Parse latitude FROM split fields (value, hemisphere).
fn parse_lat_field(value: &str, hemisphere: &str) -> error::Result<f64> {
    // WHY: NMEA fields are wire-ASCII; a non-ASCII field means the fixed
    // byte offsets below could land inside a multi-byte UTF-8 sequence and
    // panic on a &str byte-range slice. Reject non-ASCII input up front so
    // every subsequent slice index is guaranteed to be a char boundary.
    if value.len() < 4 || !value.is_ascii() {
        return Err(Error::Parse {
            message: format!("invalid latitude field: {value}"),
        });
    }
    let degrees: f64 = value[..2].parse().map_err(|_| Error::Parse {
        message: format!("invalid latitude degrees: {value}"),
    })?;
    let minutes: f64 = value[2..].parse().map_err(|_| Error::Parse {
        message: format!("invalid latitude minutes: {value}"),
    })?;
    let mut lat = degrees + minutes / 60.0;
    if hemisphere == "S" {
        lat = -lat;
    }
    Ok(lat)
}

/// Parse longitude FROM split fields (value, hemisphere).
fn parse_lon_field(value: &str, hemisphere: &str) -> error::Result<f64> {
    // WHY: NMEA fields are wire-ASCII; a non-ASCII field means the fixed
    // byte offsets below could land inside a multi-byte UTF-8 sequence and
    // panic on a &str byte-range slice. Reject non-ASCII input up front so
    // every subsequent slice index is guaranteed to be a char boundary.
    if value.len() < 5 || !value.is_ascii() {
        return Err(Error::Parse {
            message: format!("invalid longitude field: {value}"),
        });
    }
    let degrees: f64 = value[..3].parse().map_err(|_| Error::Parse {
        message: format!("invalid longitude degrees: {value}"),
    })?;
    let minutes: f64 = value[3..].parse().map_err(|_| Error::Parse {
        message: format!("invalid longitude minutes: {value}"),
    })?;
    let mut lon = degrees + minutes / 60.0;
    if hemisphere == "W" {
        lon = -lon;
    }
    Ok(lon)
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    use super::*;
    use crate::position::FixQuality;

    #[test]
    fn validate_checksum_accepts_valid_sentence() {
        let sentence = "$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76";
        assert!(
            validate_checksum(sentence).is_ok(),
            "valid GGA checksum must be accepted"
        );
    }

    #[test]
    fn validate_checksum_rejects_bad_checksum() {
        let sentence = "$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*FF";
        assert!(
            validate_checksum(sentence).is_err(),
            "corrupted checksum byte must be rejected"
        );
    }

    #[test]
    fn compute_checksum_produces_correct_value_for_gga() {
        let body = "GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,";
        assert_eq!(
            compute_checksum(body),
            0x76,
            "XOR checksum of known GGA body must be 0x76"
        );
    }

    #[test]
    fn parse_gga_extracts_position_quality_and_satellites() {
        let sentence = "$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76";
        let fix = parse_gga(sentence).expect("valid GGA sentence should parse");
        assert_eq!(
            fix.quality,
            FixQuality::Gps,
            "fix quality must be GPS for quality indicator 1"
        );
        assert_eq!(fix.satellites, 8, "satellite count must match GGA field 7");
        // 53 degrees 21.6802 minutes N = 53.36133... degrees
        assert!(
            (fix.position.lat - 53.36134).abs() < 0.001,
            "latitude must parse to ~53.361 decimal degrees"
        );
        // 6 degrees 30.3372 minutes W = -6.50562 degrees
        assert!(
            (fix.position.lon - (-6.50562)).abs() < 0.001,
            "longitude must parse to ~-6.506 decimal degrees (West = negative)"
        );
        assert!(
            (fix.position.alt.unwrap_or_default() - 61.7).abs() < 0.1,
            "altitude must parse to ~61.7 m"
        );
    }

    #[test]
    fn parse_gga_returns_error_when_no_fix() {
        let sentence = "$GPGGA,092750.000,,,,,,0,0,,,,,,,*47";
        assert!(
            parse_gga(sentence).is_err(),
            "GGA with fix quality 0 must return an error"
        );
    }

    #[test]
    fn parse_gga_returns_error_when_too_few_fields() {
        let body = "GPGGA,092750.000,5321.6802,N";
        let checksum = compute_checksum(body);
        let sentence = format!("${body}*{checksum:02X}");
        let result = parse_gga(&sentence);
        assert!(
            matches!(result, Err(Error::Parse { .. })),
            "GGA sentence with fewer than 10 fields must return Error::Parse"
        );
    }

    #[test]
    fn parse_rmc_extracts_position_speed_and_course() {
        let sentence = "$GPRMC,092750.000,A,5321.6802,N,00630.3372,W,0.02,31.66,280511,,,A*43";
        let fix = parse_rmc(sentence).expect("valid RMC sentence should parse");
        assert!(
            (fix.position.lat - 53.36134).abs() < 0.001,
            "latitude must parse to ~53.361 decimal degrees"
        );
        assert!(
            (fix.speed_knots.unwrap_or_default() - 0.02).abs() < 0.01,
            "speed must parse to ~0.02 knots"
        );
        assert!(
            (fix.course.unwrap_or_default() - 31.66).abs() < 0.01,
            "course must parse to ~31.66 degrees true"
        );
    }

    #[test]
    fn parse_rmc_returns_error_when_status_void() {
        let sentence = "$GPRMC,092750.000,V,,,,,,,280511,,,N*4C";
        assert!(
            parse_rmc(sentence).is_err(),
            "RMC with status V (void) must return an error"
        );
    }

    #[test]
    fn parse_rmc_returns_error_when_too_few_fields() {
        let body = "GPRMC,092750.000,A,5321.6802,N";
        let checksum = compute_checksum(body);
        let sentence = format!("${body}*{checksum:02X}");
        let result = parse_rmc(&sentence);
        assert!(
            matches!(result, Err(Error::Parse { .. })),
            "RMC sentence with fewer than 10 fields must return Error::Parse"
        );
    }

    #[test]
    fn parse_lat_field_converts_north_to_positive_decimal_degrees() {
        let lat = parse_lat_field("5321.6802", "N").unwrap_or_default();
        assert!(
            (lat - 53.36134).abs() < 0.001,
            "North latitude must convert to positive decimal degrees"
        );
    }

    #[test]
    fn parse_lat_field_converts_south_to_negative_decimal_degrees() {
        let lat = parse_lat_field("3348.5410", "S").unwrap_or_default();
        assert!(lat < 0.0, "South hemisphere must produce negative latitude");
        assert!(
            (lat - (-33.80902)).abs() < 0.001,
            "South latitude must convert correctly to negative decimal degrees"
        );
    }

    #[test]
    fn parse_lon_field_converts_west_to_negative_decimal_degrees() {
        let lon = parse_lon_field("00630.3372", "W").unwrap_or_default();
        assert!(lon < 0.0, "West hemisphere must produce negative longitude");
    }

    #[test]
    fn parse_lon_field_converts_east_to_positive_decimal_degrees() {
        let lon = parse_lon_field("15145.3478", "E").unwrap_or_default();
        assert!(lon > 0.0, "East hemisphere must produce positive longitude");
        assert!(
            (lon - 151.75580).abs() < 0.001,
            "East longitude must convert correctly to decimal degrees"
        );
    }

    #[test]
    fn parse_lat_field_rejects_non_ascii_instead_of_panicking() {
        let result = parse_lat_field("\u{4e00}21.6802", "N");
        assert!(
            matches!(result, Err(Error::Parse { .. })),
            "non-ASCII latitude field must return Error::Parse, not panic"
        );
    }

    #[test]
    fn parse_lon_field_rejects_non_ascii_instead_of_panicking() {
        let result = parse_lon_field("\u{4e00}030.3372", "E");
        assert!(
            matches!(result, Err(Error::Parse { .. })),
            "non-ASCII longitude field must return Error::Parse, not panic"
        );
    }

    #[test]
    fn parse_gga_never_panics_on_valid_checksum_non_ascii_coordinate() {
        let body = "GPGGA,092750.000,\u{4e00}21.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,";
        let checksum = compute_checksum(body);
        let sentence = format!("${body}*{checksum:02X}");
        let result = parse_gga(&sentence);
        assert!(
            matches!(result, Err(Error::Parse { .. })),
            "a valid-checksum sentence with a non-ASCII latitude field must error, not panic"
        );
    }

    // -- Proptest: fuzz the NMEA parser to verify no panics on arbitrary input --

    mod proptest_fuzz {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn parse_gga_never_panics(data in "\\PC{0,200}") {
                // Arbitrary strings must never cause a panic — only Ok or Err.
                let result = parse_gga(&data);
                prop_assert!(result.is_ok() || result.is_err());
            }

            #[test]
            fn parse_rmc_never_panics(data in "\\PC{0,200}") {
                let result = parse_rmc(&data);
                prop_assert!(result.is_ok() || result.is_err());
            }

            #[test]
            fn validate_checksum_never_panics(data in "\\PC{0,200}") {
                let result = validate_checksum(&data);
                prop_assert!(result.is_ok() || result.is_err());
            }

            #[test]
            fn parse_gga_never_panics_on_valid_checksum_multibyte_coordinate(c in "\\PC") {
                // WHY: the random-byte proptests above fail checksum validation
                // before reaching the slice, so they never exercise a
                // valid-checksum sentence with a multi-byte coordinate field.
                let body = format!("GPGGA,092750.000,{c}21.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,");
                let checksum = compute_checksum(&body);
                let sentence = format!("${body}*{checksum:02X}");
                let result = parse_gga(&sentence);
                prop_assert!(result.is_ok() || result.is_err());
            }
        }
    }
}
