//! NMEA 0183 sentence parser.
//!
//! Parses standard GPS sentences: GGA (fix data), RMC (recommended minimum),
//! GSA (DOP and active satellites), GSV (satellites in view).

use crate::error::{self, Error};
use crate::position::{Fix, FixQuality, Position};

/// Validate NMEA checksum. The checksum is the XOR of all bytes between '$' and '*'.
pub fn validate_checksum(sentence: &str) -> Result<(), Error> {
    let inner = sentence
        .strip_prefix('$')
        .and_then(|s| s.split('*').next())
        .ok_or_else(|| Error::ParseError {
            message: "missing $ prefix or * checksum delimiter".to_owned(),
        })?;

    let expected_str =
        sentence
            .split('*')
            .nth(1)
            .map(str::trim)
            .ok_or_else(|| Error::ParseError {
                message: "missing checksum after *".to_owned(),
            })?;

    let expected = u8::from_str_radix(expected_str, 16).map_err(|_| Error::ParseError {
        message: format!("invalid checksum hex: {expected_str}"),
    })?;

    let actual = inner.bytes().fold(0u8, |acc, b| acc ^ b);

    if actual == expected {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch { expected, actual })
    }
}

/// Compute NMEA checksum for a sentence body (without $ and *).
pub fn compute_checksum(body: &str) -> u8 {
    body.bytes().fold(0u8, |acc, b| acc ^ b)
}

/// Parse a GGA sentence (Global Positioning System Fix Data).
///
/// Format: `$GPGGA,hhmmss.ss,llll.ll,a,yyyyy.yy,a,x,xx,x.x,x.x,M,x.x,M,x.x,xxxx*hh`
pub fn parse_gga(sentence: &str) -> error::Result<Fix> {
    validate_checksum(sentence)?;

    let body = sentence
        .strip_prefix('$')
        .and_then(|s| s.split('*').next())
        .ok_or_else(|| Error::ParseError {
            message: "invalid GGA sentence".to_owned(),
        })?;

    let fields: Vec<&str> = body.split(',').collect();
    if fields.len() < 10 {
        return Err(Error::ParseError {
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
pub fn parse_rmc(sentence: &str) -> error::Result<Fix> {
    validate_checksum(sentence)?;

    let body = sentence
        .strip_prefix('$')
        .and_then(|s| s.split('*').next())
        .ok_or_else(|| Error::ParseError {
            message: "invalid RMC sentence".to_owned(),
        })?;

    let fields: Vec<&str> = body.split(',').collect();
    if fields.len() < 10 {
        return Err(Error::ParseError {
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
    if value.len() < 4 {
        return Err(Error::ParseError {
            message: format!("latitude too short: {value}"),
        });
    }
    let degrees: f64 = value[..2].parse().map_err(|_| Error::ParseError {
        message: format!("invalid latitude degrees: {value}"),
    })?;
    let minutes: f64 = value[2..].parse().map_err(|_| Error::ParseError {
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
    if value.len() < 5 {
        return Err(Error::ParseError {
            message: format!("longitude too short: {value}"),
        });
    }
    let degrees: f64 = value[..3].parse().map_err(|_| Error::ParseError {
        message: format!("invalid longitude degrees: {value}"),
    })?;
    let minutes: f64 = value[3..].parse().map_err(|_| Error::ParseError {
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

    // -- Proptest: fuzz the NMEA parser to verify no panics on arbitrary input --

    mod proptest_fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn parse_gga_never_panics(data in "\\PC{0,200}") {
                // Arbitrary strings must never cause a panic — only Ok or Err.
                let _ = parse_gga(&data);
            }

            #[test]
            fn parse_rmc_never_panics(data in "\\PC{0,200}") {
                let _ = parse_rmc(&data);
            }

            #[test]
            fn validate_checksum_never_panics(data in "\\PC{0,200}") {
                let _ = validate_checksum(&data);
            }
        }
    }
}
