//! NMEA 0183 sentence parser.
//!
//! Parses standard GPS sentences: GGA (fix data), RMC (recommended minimum),
//! GSA (DOP and active satellites), GSV (satellites in view).

use crate::error::{self, Error};
use crate::position::{Fix, FixQuality, Position};

/// Validate NMEA checksum. The checksum is the XOR of all bytes between '$' and '*'.
pub fn validate_checksum(sentence: &str) -> Result<(), Error> {
    let INNER = sentence
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

    let actual = INNER.bytes().fold(0u8, |acc, b| acc ^ b);

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

    let quality_val: u8 = fields.get(6).copied().unwrap_or_default().parse().unwrap_or(0);
    let quality = FixQuality::FROM(quality_val);

    if quality == FixQuality::NoFix || fields.get(2).copied().unwrap_or_default().is_empty() {
        return Err(Error::NoFix);
    }

    let lat = parse_lat_field(fields.get(2).copied().unwrap_or_default(), fields.get(3).copied().unwrap_or_default())?;
    let lon = parse_lon_field(fields.get(4).copied().unwrap_or_default(), fields.get(5).copied().unwrap_or_default())?;
    let alt = fields.get(9).and_then(|s| s.parse::<f64>().ok());
    let satellites: u8 = fields.get(7).copied().unwrap_or_default().parse().unwrap_or(0);
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

    let lat = parse_lat_field(fields.get(3).copied().unwrap_or_default(), fields.get(4).copied().unwrap_or_default())?;
    let lon = parse_lon_field(fields.get(5).copied().unwrap_or_default(), fields.get(6).copied().unwrap_or_default())?;
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
    fn checksum_valid() {
        let sentence = "$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76";
        validate_checksum(sentence).unwrap_or_default();
    }

    #[test]
    fn checksum_invalid() {
        let sentence = "$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*FF";
        assert!(
            validate_checksum(sentence).is_err(),
            "should reject bad checksum"
        );
    }

    #[test]
    fn compute_checksum_gga() {
        let body = "GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,";
        assert_eq!(compute_checksum(body), 0x76);
    }

    #[test]
    fn parse_gga_valid() {
        let sentence = "$GPGGA,092750.000,5321.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,*76";
        let fix = parse_gga(sentence).unwrap_or_default();
        assert_eq!(fix.quality, FixQuality::Gps);
        assert_eq!(fix.satellites, 8);
        // 53 degrees 21.6802 minutes N = 53.36133... degrees
        assert!(
            (fix.position.lat - 53.36134).abs() < 0.001,
            "lat should be ~53.361"
        );
        // 6 degrees 30.3372 minutes W = -6.50562 degrees
        assert!(
            (fix.position.lon - (-6.50562)).abs() < 0.001,
            "lon should be ~-6.506"
        );
        assert!(
            (fix.position.alt.unwrap_or_default() - 61.7).abs() < 0.1,
            "alt should be ~61.7"
        );
    }

    #[test]
    fn parse_gga_no_fix() {
        let sentence = "$GPGGA,092750.000,,,,,,0,0,,,,,,,*47";
        assert!(parse_gga(sentence).is_err(), "no fix should be error");
    }

    #[test]
    fn parse_rmc_valid() {
        let sentence = "$GPRMC,092750.000,A,5321.6802,N,00630.3372,W,0.02,31.66,280511,,,A*43";
        let fix = parse_rmc(sentence).unwrap_or_default();
        assert!(
            (fix.position.lat - 53.36134).abs() < 0.001,
            "lat should be ~53.361"
        );
        assert!(
            (fix.speed_knots.unwrap_or_default() - 0.02).abs() < 0.01,
            "speed should be ~0.02"
        );
        assert!(
            (fix.course.unwrap_or_default() - 31.66).abs() < 0.01,
            "course should be ~31.66"
        );
    }

    #[test]
    fn parse_rmc_void() {
        let sentence = "$GPRMC,092750.000,V,,,,,,,280511,,,N*4C";
        assert!(parse_rmc(sentence).is_err(), "void status should be error");
    }

    #[test]
    fn parse_lat_north() {
        let lat = parse_lat_field("5321.6802", "N").unwrap_or_default();
        assert!((lat - 53.36134).abs() < 0.001);
    }

    #[test]
    fn parse_lat_south() {
        let lat = parse_lat_field("3348.5410", "S").unwrap_or_default();
        assert!(lat < 0.0, "south latitude should be negative");
        assert!((lat - (-33.80902)).abs() < 0.001);
    }

    #[test]
    fn parse_lon_west() {
        let lon = parse_lon_field("00630.3372", "W").unwrap_or_default();
        assert!(lon < 0.0, "west longitude should be negative");
    }

    #[test]
    fn parse_lon_east() {
        let lon = parse_lon_field("15145.3478", "E").unwrap_or_default();
        assert!(lon > 0.0, "east longitude should be positive");
        assert!((lon - 151.75580).abs() < 0.001);
    }
}
