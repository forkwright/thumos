//! Geographic position types.

pub(crate) use topos_core::FixQuality;

/// A geographic coordinate with latitude, longitude, and optional altitude.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Position {
    /// Latitude in decimal degrees. Positive = North, negative = South.
    pub(crate) lat: f64,
    /// Longitude in decimal degrees. Positive = East, negative = West.
    pub(crate) lon: f64,
    /// Altitude above mean sea level in meters. None if not available.
    pub(crate) alt: Option<f64>,
}

impl From<topos_core::Position> for Position {
    // WHY: topos_core::Position stores microdegrees as i64 (bounded to
    // +/-180 * 1_000_000 by topos_core's own range checks -- nowhere near
    // f64's 53-bit exact-integer range), so the i64 -> f64 widening below
    // never loses precision in practice; `cast_precision_loss` cannot see
    // that value-range invariant, only the types.
    #[expect(
        clippy::cast_precision_loss,
        reason = "microdegrees are bounded to +/-180_000_000, far inside f64's exact range"
    )]
    fn from(p: topos_core::Position) -> Self {
        Self {
            lat: p.lat_udeg as f64 / topos_core::MICRODEG_SCALE as f64,
            lon: p.lon_udeg as f64 / topos_core::MICRODEG_SCALE as f64,
            alt: None,
        }
    }
}

/// A complete GPS fix with position, quality, and satellite info.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Fix {
    /// Geographic position.
    pub(crate) position: Position,
    /// Fix quality.
    pub(crate) quality: FixQuality,
    /// Number of satellites in use.
    pub(crate) satellites: u8,
    /// Horizontal dilution of precision.
    pub(crate) hdop: Option<f64>,
    /// Speed over ground in knots.
    pub(crate) speed_knots: Option<f64>,
    /// Course over ground in degrees true.
    pub(crate) course: Option<f64>,
}
