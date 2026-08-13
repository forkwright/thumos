//! NMEA 0183 sentence parser.
//!
//! Parses the sentence types this crate has an implementation for: GGA
//! (fix data) and RMC (recommended minimum). Checksum framing, coordinate
//! conversion, fix-quality classification, and the GGA/RMC field layout are
//! canonical in [`topos_core`] (#545), shared with the kernel's GPS driver.

use crate::error;
use crate::position::{Fix, Position};

/// Extract field `index` from a checksummed sentence.
///
/// HDOP, speed, and course carry no NMEA-specific parsing beyond
/// `str::parse` -- there is no protocol invariant here worth sharing with
/// the kernel, which does not read any of the three. WHY re-tokenizing
/// rather than threading these out of [`topos_core::parse_gga`] /
/// [`topos_core::parse_rmc`]: those functions return the position/fix
/// invariants both consumers care about; bolting three kernel-unused
/// floats onto that shared type would widen the surface the kernel has to
/// ignore for no shared benefit.
fn field(sentence: &str, index: usize) -> Option<&str> {
    let body = topos_core::checksum_body(sentence.as_bytes()).ok()?;
    let raw = topos_core::split_fields(body).get(index).copied()?;
    std::str::from_utf8(raw).ok()
}

/// Parse a GGA sentence (Global Positioning System Fix Data).
///
/// Format: `$GPGGA,hhmmss.ss,llll.ll,a,yyyyy.yy,a,x,xx,x.x,x.x,M,x.x,M,x.x,xxxx*hh`
///
/// Time: O(n) where n is `sentence.len()` in bytes -- `topos_core::parse_gga`
/// makes one checksum + one field-split pass over the sentence, and the
/// local `field` helper re-derives HDOP by repeating both passes; a
/// constant number of linear passes is still O(n).
/// Space: O(f) where f is the number of comma-separated fields the
/// sentence splits into (each `split_fields` call allocates a `Vec` of
/// field slices that borrow the original bytes rather than copying them;
/// f is bounded by n in the worst case of an all-comma input).
pub(crate) fn parse_gga(sentence: &str) -> error::Result<Fix> {
    let core_fix = topos_core::parse_gga(sentence.as_bytes())?;
    let mut position = Position::from(core_fix.position);
    position.alt = core_fix.altitude_mm.map(|mm| f64::from(mm) / 1000.0);

    Ok(Fix {
        position,
        quality: core_fix.quality,
        satellites: core_fix.satellite_count,
        hdop: field(sentence, 8).and_then(|s| s.parse::<f64>().ok()),
        speed_knots: None,
        course: None,
    })
}

/// Parse a RMC sentence (Recommended Minimum Navigation Information).
///
/// Format: `$GPRMC,hhmmss.ss,A,llll.ll,a,yyyyy.yy,a,x.x,x.x,ddmmyy,x.x,a*hh`
///
/// Returns the fix alongside the extracted UTC date/time -- a capability
/// this crate did not have before #545 converged it with the kernel's GPS
/// driver, which uses RMC time for clock synchronization.
///
/// Time: O(n) where n is `sentence.len()` in bytes -- `topos_core::parse_rmc`
/// makes one checksum + one field-split pass, and the local `field` helper
/// repeats both passes once per extracted field (speed, course); a
/// constant number of linear passes is still O(n).
/// Space: O(f) where f is the number of comma-separated fields the
/// sentence splits into (each `split_fields` call allocates a `Vec` of
/// borrowed field slices; f is bounded by n in the worst case).
pub(crate) fn parse_rmc(sentence: &str) -> error::Result<(Fix, topos_core::DateTime)> {
    let (core_fix, time) = topos_core::parse_rmc(sentence.as_bytes())?;

    let fix = Fix {
        position: Position::from(core_fix.position),
        quality: core_fix.quality,
        satellites: core_fix.satellite_count,
        hdop: None,
        speed_knots: field(sentence, 7).and_then(|s| s.parse::<f64>().ok()),
        course: field(sentence, 8).and_then(|s| s.parse::<f64>().ok()),
    };
    Ok((fix, time))
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::position::FixQuality;

    /// Build a valid-checksum NMEA sentence "$<body>*<XX>" for tests.
    fn nmea_sentence(body: &str) -> String {
        let checksum = topos_core::compute_checksum(body.as_bytes());
        format!("${body}*{checksum:02X}")
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
        // 53 degrees 21.6802 minutes N = 53.36134... degrees
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
        assert!(
            (fix.hdop.unwrap_or_default() - 1.03).abs() < 0.001,
            "HDOP must parse to ~1.03"
        );
    }

    #[test]
    fn parse_gga_returns_error_when_no_fix() {
        // WHY the computed-checksum helper rather than a literal: the
        // fixture this replaced hardcoded "*47" for this exact body text,
        // whose real XOR checksum is 0x6D. The test still passed, but for
        // the wrong reason -- it exercised the checksum-mismatch path, not
        // the quality-zero path it claimed to cover. Found while comparing
        // this fixture against the kernel's equivalent, which used the
        // correct checksum (#545).
        let sentence = nmea_sentence("GPGGA,092750.000,,,,,,0,0,,,,,,,");
        assert_eq!(
            parse_gga(&sentence),
            Err(Error::NoFix),
            "GGA with fix quality 0 must return Error::NoFix specifically, \
             not merely any error"
        );
    }

    #[test]
    fn parse_gga_returns_error_when_too_few_fields() {
        let sentence = nmea_sentence("GPGGA,092750.000,5321.6802,N");
        let result = parse_gga(&sentence);
        assert!(
            matches!(result, Err(Error::Parse { .. })),
            "GGA sentence with fewer than 10 fields must return Error::Parse"
        );
    }

    #[test]
    fn parse_rmc_extracts_position_speed_and_course() {
        let sentence = "$GPRMC,092750.000,A,5321.6802,N,00630.3372,W,0.02,31.66,280511,,,A*43";
        let (fix, _time) = parse_rmc(sentence).expect("valid RMC sentence should parse");
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
    fn parse_rmc_extracts_time() {
        // Before #545 this crate never extracted RMC time/date at all --
        // there was nothing here to compare against the kernel's
        // equivalent. Converging onto the shared core gains the capability.
        let sentence = "$GPRMC,092750.000,A,5321.6802,N,00630.3372,W,0.02,31.66,280511,,,A*43";
        let (_fix, time) = parse_rmc(sentence).expect("valid RMC sentence should parse");
        assert_eq!(
            time,
            topos_core::DateTime {
                year: 2011,
                month: 5,
                day: 28,
                hour: 9,
                minute: 27,
                second: 50,
            },
            "RMC time/date fields must be extracted, matching the kernel's equivalent"
        );
    }

    #[test]
    fn parse_rmc_returns_error_when_status_void() {
        let sentence = nmea_sentence("GPRMC,092750.000,V,5321.6802,N,00630.3372,W,,,280511,,,A");
        assert_eq!(
            parse_rmc(&sentence),
            Err(Error::NoFix),
            "RMC with status V (void) must return Error::NoFix"
        );
    }

    #[test]
    fn parse_rmc_returns_error_when_too_few_fields() {
        let sentence = nmea_sentence("GPRMC,092750.000,A,5321.6802,N");
        let result = parse_rmc(&sentence);
        assert!(
            matches!(result, Err(Error::Parse { .. })),
            "RMC sentence with fewer than 10 fields must return Error::Parse"
        );
    }

    // -- Proptest: fuzz the parser to verify no panics on arbitrary input --
    //
    // Byte-oriented parsing in topos_core removes the char-boundary panic
    // risk that motivated the old ASCII-only guards in this crate's
    // str-slicing parser (a non-ASCII coordinate field could land a `&str`
    // byte-range slice inside a multi-byte sequence). These properties
    // confirm arbitrary Unicode input -- not just arbitrary ASCII -- still
    // never panics through the delegating wrapper.
    //
    // NOTE: no `prop_assert!` follows each call. The property under test is
    // "does not panic", which proptest's harness already enforces by running
    // the body and catching any panic as a shrunk failing case -- a
    // `result.is_ok() || result.is_err()` line would be true for every
    // possible `Result`, asserting nothing beyond what the harness already
    // guarantees. The `Result` is deliberately discarded: both outcomes are
    // valid for arbitrary/fuzzed input.
    mod proptest_fuzz {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn parse_gga_never_panics(data in "\\PC{0,200}") {
                // kanon:ignore TESTING/tautological-test -- proptest's harness IS the verification signal for "never panics" (see NOTE above); no `should_panic`-shaped carve-out exists for the inverse (never-panics) case, so this documents the equivalent invariant explicitly.
                let _ = parse_gga(&data);
            }

            #[test]
            fn parse_rmc_never_panics(data in "\\PC{0,200}") {
                // kanon:ignore TESTING/tautological-test -- proptest's harness IS the verification signal for "never panics" (see NOTE above).
                let _ = parse_rmc(&data);
            }

            #[test]
            fn checksum_body_never_panics(data in "\\PC{0,200}") {
                // kanon:ignore TESTING/tautological-test -- proptest's harness IS the verification signal for "never panics" (see NOTE above).
                let _ = topos_core::checksum_body(data.as_bytes());
            }

            #[test]
            fn parse_gga_never_panics_on_valid_checksum_multibyte_coordinate(c in "\\PC") {
                // kanon:ignore TESTING/tautological-test -- proptest's harness IS the verification signal for "never panics" (see NOTE above).
                // WHY: the random-byte proptests above fail checksum validation
                // before reaching the slice, so they never exercise a
                // valid-checksum sentence with a multi-byte coordinate field.
                let body = format!("GPGGA,092750.000,{c}21.6802,N,00630.3372,W,1,8,1.03,61.7,M,55.2,M,,");
                let sentence = nmea_sentence(&body);
                let _ = parse_gga(&sentence);
            }
        }
    }
}
